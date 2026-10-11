require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
 console.error('Faltan DATABASE_URL o SESSION_SECRET en el entorno'); process.exit(1);
}
const production = process.env.NODE_ENV === 'production';
const pool = new Pool({connectionString:process.env.DATABASE_URL,ssl:production?{rejectUnauthorized:false}:false});
const app = express();
if(production) app.set('trust proxy',1);
app.set('view engine','ejs');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.urlencoded({extended:false,limit:'25kb'}));
app.use(express.static(path.join(__dirname,'public')));
app.use(session({store:new PgSession({pool,createTableIfMissing:true}),secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,secure:production,sameSite:'lax',maxAge:8*60*60*1000}}));
app.use((req,res,next)=>{
 if(!req.session.csrf) req.session.csrf=crypto.randomBytes(24).toString('hex');
 res.locals.csrf=req.session.csrf;
 res.locals.user=req.session.user||null;
 res.locals.message=req.session.message||null;
 delete req.session.message;
 next();
});
function message(req,text){req.session.message=text;}
function csrf(req,res,next){if(req.body._csrf!==req.session.csrf)return res.status(403).send('Formulario inválido. Recarga la página.');next();}
function auth(req,res,next){if(!req.session.user)return res.redirect('/login');next();}
function admin(req,res,next){if(req.session.user?.role!=='admin')return res.status(403).send('Acceso denegado');next();}
function validTicket(letter,number){return /^[A-Z]$/.test(letter)&&Number.isInteger(number)&&number>=1&&number<=100;}
const money=n=>'$'+Number(n).toLocaleString('es-CL');
app.locals.money=money;
app.get('/login',(req,res)=>res.render('login'));
app.get('/premios',(req,res)=>res.render('prizes'));

app.post('/login',csrf,async(req,res,next)=>{try{
 const username=String(req.body.username||'').trim().toLowerCase();
 const {rows}=await pool.query('SELECT * FROM users WHERE username=$1 AND active=true',[username]);
 const user=rows[0];
 if(!user||!await bcrypt.compare(String(req.body.password||''),user.password_hash)){message(req,'Usuario o contraseña incorrectos');return res.redirect('/login');}
 req.session.regenerate(err=>{if(err)return next(err);req.session.user={id:user.id,username:user.username,role:user.role};req.session.csrf=crypto.randomBytes(24).toString('hex');res.redirect('/');});
}catch(e){next(e)}});
app.post('/logout',csrf,(req,res)=>req.session.destroy(()=>res.redirect('/login')));
app.get('/',auth,async(req,res,next)=>{try{
 const stats=await pool.query("SELECT status,COUNT(*)::int AS qty FROM tickets GROUP BY status");
 const letters=await pool.query("SELECT letter, COUNT(*) FILTER (WHERE status='available')::int AS available, COUNT(*) FILTER (WHERE status='reserved')::int AS reserved, COUNT(*) FILTER (WHERE status='paid')::int AS paid FROM tickets GROUP BY letter ORDER BY letter");
 const summary=Object.fromEntries(stats.rows.map(x=>[x.status,x.qty]));
 const physical=await pool.query('SELECT letter,responsible FROM physical_letters');
 res.render('dashboard',{summary,letters:letters.rows,physical:physical.rows});
}catch(e){next(e)}});
app.get('/rifa/:letter',auth,async(req,res,next)=>{try{
 const letter=String(req.params.letter||'').toUpperCase();
 if(!/^[A-Z]$/.test(letter))return res.status(404).send('Rifa inexistente');
 const {rows}=await pool.query('SELECT t.*,u.username AS seller FROM tickets t LEFT JOIN users u ON u.id=t.seller_id WHERE letter=$1 ORDER BY number',[letter]);
 const blocked=await pool.query('SELECT responsible FROM physical_letters WHERE letter=$1',[letter]);
 res.render('tickets',{letter,tickets:rows,physical:blocked.rows[0]||null});
}catch(e){next(e)}});
app.post('/tickets/reserve',auth,csrf,async(req,res,next)=>{
 const letter=String(req.body.letter||'').toUpperCase();
 const nums=[...new Set(String(req.body.numbers||'').split(',').map(s=>Number(s.trim())))];
 const buyer=String(req.body.buyer_name||'').trim();
 const phone=String(req.body.buyer_phone||'').trim();
 if(!/^[A-Z]$/.test(letter)||!nums.length||nums.length>100||nums.some(n=>!validTicket(letter,n))||buyer.length<2||buyer.length>120||phone.length<5||phone.length>40){message(req,'Revisa los números y los datos del comprador');return res.redirect('/rifa/'+( /^[A-Z]$/.test(letter)?letter:'A'));}
 const client=await pool.connect();
 try{
 await client.query('BEGIN');
 await client.query('SELECT pg_advisory_xact_lock($1)',[letter.charCodeAt(0)]);
 const blocked=await client.query('SELECT 1 FROM physical_letters WHERE letter=$1',[letter]);
 if(blocked.rowCount){await client.query('ROLLBACK');message(req,'Esta letra está asignada a venta física.');return res.redirect('/rifa/'+letter);}
 const {rows}=await client.query('SELECT number,status FROM tickets WHERE letter=$1 AND number=ANY($2::smallint[]) FOR UPDATE',[letter,nums]);
 if(rows.length!==nums.length||rows.some(t=>t.status!=='available')){await client.query('ROLLBACK');message(req,'Uno o más números ya no están disponibles. No se guardó la venta.');return res.redirect('/rifa/'+letter);}
 for(const n of nums){
 await client.query("UPDATE tickets SET status='reserved',buyer_name=$1,buyer_phone=$2,seller_id=$3,updated_at=NOW() WHERE letter=$4 AND number=$5",[buyer,phone,req.session.user.id,letter,n]);
 await client.query("INSERT INTO audit_log(letter,number,actor_id,action,previous_status,new_status) VALUES($1,$2,$3,'reserve','available','reserved')",[letter,n,req.session.user.id]);
 }
 await client.query('COMMIT');message(req,`Se reservaron ${nums.length} número(s) para ${buyer}.`);res.redirect('/rifa/'+letter);
 }catch(e){await client.query('ROLLBACK');next(e)}finally{client.release()}
});
app.post('/tickets/:letter/:number/:action',auth,csrf,async(req,res,next)=>{
 const letter=String(req.params.letter||'').toUpperCase(),number=Number(req.params.number),action=req.params.action;
 if(!validTicket(letter,number)||!['pay','release'].includes(action))return res.status(400).send('Solicitud inválida');
 const client=await pool.connect();
 try{
 await client.query('BEGIN');
 const {rows}=await client.query('SELECT * FROM tickets WHERE letter=$1 AND number=$2 FOR UPDATE',[letter,number]);
 const ticket=rows[0];
 if(!ticket||ticket.status!=='reserved'||(req.session.user.role!=='admin'&&Number(ticket.seller_id)!==Number(req.session.user.id))){await client.query('ROLLBACK');message(req,'No tienes permiso o el número ya cambió de estado.');return res.redirect('/rifa/'+letter);}
 const newStatus=action==='pay'?'paid':'available';
 if(action==='pay')await client.query("UPDATE tickets SET status='paid',updated_at=NOW() WHERE letter=$1 AND number=$2",[letter,number]);
 else await client.query("UPDATE tickets SET status='available',buyer_name=NULL,buyer_phone=NULL,seller_id=NULL,updated_at=NOW() WHERE letter=$1 AND number=$2",[letter,number]);
 await client.query('INSERT INTO audit_log(letter,number,actor_id,action,previous_status,new_status) VALUES($1,$2,$3,$4,$5,$6)',[letter,number,req.session.user.id,action,ticket.status,newStatus]);
 await client.query('COMMIT');message(req,action==='pay'?'Pago confirmado':'Reserva liberada');res.redirect('/rifa/'+letter);
 }catch(e){await client.query('ROLLBACK');next(e)}finally{client.release()}
});

// v1.1: gestión de letras físicas, con bloqueo de concurrencia por letra.
app.get('/admin/fisicas',auth,admin,async(req,res,next)=>{try{
 const letters=await pool.query(`SELECT t.letter,COUNT(*) FILTER(WHERE t.status!='available')::int AS occupied,p.responsible FROM tickets t LEFT JOIN physical_letters p ON p.letter=t.letter GROUP BY t.letter,p.responsible ORDER BY t.letter`);
 res.render('physical',{letters:letters.rows});
}catch(e){next(e)}});
app.post('/admin/fisicas/:letter/block',auth,admin,csrf,async(req,res,next)=>{
 const letter=String(req.params.letter).toUpperCase(),responsible=String(req.body.responsible||'').trim();
 if(!/^[A-Z]$/.test(letter)||responsible.length<2||responsible.length>120)return res.status(400).send('Datos inválidos');
 const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock($1)',[letter.charCodeAt(0)]);
 const count=await c.query("SELECT COUNT(*)::int AS n FROM tickets WHERE letter=$1 AND status!='available'",[letter]);
 if(count.rows[0].n){await c.query('ROLLBACK');message(req,'No se puede bloquear una letra que ya tiene reservas o pagos.');return res.redirect('/admin/fisicas');}
 await c.query('INSERT INTO physical_letters(letter,responsible,created_by) VALUES($1,$2,$3) ON CONFLICT(letter) DO NOTHING',[letter,responsible,req.session.user.id]);await c.query('COMMIT');message(req,'Letra asignada a venta física');res.redirect('/admin/fisicas');
 }catch(e){await c.query('ROLLBACK');next(e)}finally{c.release()}
});
app.post('/admin/fisicas/:letter/unblock',auth,admin,csrf,async(req,res,next)=>{
 const letter=String(req.params.letter).toUpperCase();if(!/^[A-Z]$/.test(letter))return res.status(400).send('Letra inválida');
 const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock($1)',[letter.charCodeAt(0)]);
 await c.query('DELETE FROM physical_letters WHERE letter=$1',[letter]);await c.query('COMMIT');message(req,'Letra habilitada para venta digital; confirma primero que la lista física fue devuelta y conciliada.');res.redirect('/admin/fisicas');
 }catch(e){await c.query('ROLLBACK');next(e)}finally{c.release()}
});
app.get('/admin/fisicas/:letter/imprimir',auth,admin,async(req,res,next)=>{try{
 const letter=String(req.params.letter).toUpperCase();if(!/^[A-Z]$/.test(letter))return res.status(400).send('Letra inválida');
 const {rows}=await pool.query('SELECT responsible FROM physical_letters WHERE letter=$1',[letter]);if(!rows.length)return res.status(404).send('Primero bloquea esta letra');
 res.render('print',{letter,responsible:rows[0].responsible});
}catch(e){next(e)}});
// Registrar números vendidos en papel: solo administrador y letra bloqueada.
app.post('/admin/fisicas/:letter/sale',auth,admin,csrf,async(req,res,next)=>{
 const letter=String(req.params.letter).toUpperCase(),number=Number(req.body.number),buyer=String(req.body.buyer_name||'').trim(),phone=String(req.body.buyer_phone||'').trim(),paid=req.body.paid==='yes';
 if(!validTicket(letter,number)||buyer.length<2||buyer.length>120||phone.length<5||phone.length>40){message(req,'Datos de venta física inválidos');return res.redirect('/admin/fisicas');}
 const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock($1)',[letter.charCodeAt(0)]);
 const blocked=await c.query('SELECT 1 FROM physical_letters WHERE letter=$1',[letter]);if(!blocked.rowCount)throw new Error('Letra no bloqueada');
 const result=await c.query("UPDATE tickets SET status=$1,buyer_name=$2,buyer_phone=$3,seller_id=$4,updated_at=NOW() WHERE letter=$5 AND number=$6 AND status='available' RETURNING number",[paid?'paid':'reserved',buyer,phone,req.session.user.id,letter,number]);
 if(!result.rowCount){await c.query('ROLLBACK');message(req,'Ese número ya está ocupado.');return res.redirect('/admin/fisicas');}
 await c.query('INSERT INTO audit_log(letter,number,actor_id,action,previous_status,new_status) VALUES($1,$2,$3,$4,$5,$6)',[letter,number,req.session.user.id,'physical_sale','available',paid?'paid':'reserved']);await c.query('COMMIT');message(req,'Venta física registrada');res.redirect('/admin/fisicas');
 }catch(e){await c.query('ROLLBACK');next(e)}finally{c.release()}
});
app.get('/compradores',auth,async(req,res,next)=>{try{
 const q=String(req.query.q||'').trim().slice(0,100);let rows=[];
 if(q){const args=['%'+q+'%'];let where="(t.buyer_name ILIKE $1 OR t.buyer_phone ILIKE $1 OR (t.letter||'-'||LPAD(t.number::text,2,'0')) ILIKE $1)";
 if(req.session.user.role!=='admin'){args.push(req.session.user.id);where+=' AND t.seller_id=$2';}
 const result=await pool.query(`SELECT t.*,u.username AS seller FROM tickets t LEFT JOIN users u ON u.id=t.seller_id WHERE t.status!='available' AND ${where} ORDER BY t.buyer_name,t.letter,t.number LIMIT 150`,args);rows=result.rows;}
 res.render('buyers',{q,rows});
}catch(e){next(e)}});
app.post('/admin/cancel',auth,admin,csrf,async(req,res,next)=>{
 const letter=String(req.body.letter||'').toUpperCase(),number=Number(req.body.number),reason=String(req.body.reason||'').trim(),refund=String(req.body.refund_state||'');
 if(!validTicket(letter,number)||reason.length<5||reason.length>500||!['refunded','pending','not_applicable'].includes(refund))return res.status(400).send('Datos inválidos');
 const c=await pool.connect();try{await c.query('BEGIN');const {rows}=await c.query('SELECT * FROM tickets WHERE letter=$1 AND number=$2 FOR UPDATE',[letter,number]);const t=rows[0];
 if(!t||t.status!=='paid'){await c.query('ROLLBACK');message(req,'El número no está pagado');return res.redirect('/rifa/'+letter);}
 await c.query('INSERT INTO cancellation_details(letter,number,buyer_name,buyer_phone,seller_id,cancelled_by,reason,refund_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[letter,number,t.buyer_name,t.buyer_phone,t.seller_id,req.session.user.id,reason,refund]);
 await c.query("UPDATE tickets SET status='available',buyer_name=NULL,buyer_phone=NULL,seller_id=NULL,updated_at=NOW() WHERE letter=$1 AND number=$2",[letter,number]);
 await c.query("INSERT INTO audit_log(letter,number,actor_id,action,previous_status,new_status) VALUES($1,$2,$3,'cancel','paid','available')",[letter,number,req.session.user.id]);
 await c.query('COMMIT');message(req,'Venta anulada. Revisa la devolución del dinero por separado.');res.redirect('/rifa/'+letter);
 }catch(e){await c.query('ROLLBACK');next(e)}finally{c.release()}
});
app.get('/admin/anulaciones',auth,admin,async(req,res,next)=>{try{const {rows}=await pool.query('SELECT c.*,u.username AS actor FROM cancellation_details c LEFT JOIN users u ON u.id=c.cancelled_by ORDER BY c.id DESC LIMIT 300');res.render('cancellations',{rows});}catch(e){next(e)}});
// Exportación CSV de datos, NO sustituye un respaldo PostgreSQL restaurable.
app.get('/admin/exportar',auth,admin,async(req,res,next)=>{try{
 const {rows}=await pool.query("SELECT letter,number,status,buyer_name,buyer_phone,seller_id,updated_at FROM tickets WHERE status!='available' ORDER BY letter,number");
 const esc=v=>'"'+String(v??'').replace(/^[=+@-]/,"' $&").replace(/"/g,'""')+'"';
 const cols=['letter','number','status','buyer_name','buyer_phone','seller_id','updated_at'];
 res.set('Content-Type','text/csv; charset=utf-8');res.set('Content-Disposition','attachment; filename="rifa-participaciones.csv"');res.send('﻿'+cols.join(',')+'\n'+rows.map(r=>cols.map(k=>esc(r[k])).join(',')).join('\n'));
}catch(e){next(e)}});

app.get('/admin/users',auth,admin,async(req,res,next)=>{try{const {rows}=await pool.query('SELECT id,username,role,active,created_at FROM users ORDER BY id');res.render('users',{users:rows});}catch(e){next(e)}});
app.post('/admin/users',auth,admin,csrf,async(req,res,next)=>{try{
 const username=String(req.body.username||'').trim().toLowerCase(),password=String(req.body.password||'');
 if(!/^[a-z0-9_.-]{3,60}$/.test(username)||password.length<10){message(req,'Usuario inválido o contraseña menor a 10 caracteres');return res.redirect('/admin/users');}
 const hash=await bcrypt.hash(password,12);
 await pool.query("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'seller')",[username,hash]);message(req,'Vendedor creado');res.redirect('/admin/users');
 }catch(e){if(e.code==='23505'){message(req,'Ese usuario ya existe');return res.redirect('/admin/users')}next(e)}});
app.post('/admin/users/:id/toggle',auth,admin,csrf,async(req,res,next)=>{try{
 const id=Number(req.params.id);if(!Number.isSafeInteger(id)||id===Number(req.session.user.id))return res.status(400).send('No puedes bloquear tu propia cuenta');
 await pool.query("UPDATE users SET active=NOT active WHERE id=$1 AND role='seller'",[id]);message(req,'Estado actualizado');res.redirect('/admin/users');
}catch(e){next(e)}});
// Revoca sesiones de cuentas desactivadas en cada petición protegida.
app.use((err,req,res,next)=>{console.error(err);res.status(500).send('Ocurrió un error. Intenta nuevamente.');});
async function start(){
 const sql=fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8');await pool.query(sql);
 if(process.env.ADMIN_USER&&process.env.ADMIN_PASSWORD){
  const username=process.env.ADMIN_USER.toLowerCase();
  const found=await pool.query('SELECT id FROM users WHERE username=$1',[username]);
  if(!found.rowCount){if(process.env.ADMIN_PASSWORD.length<10)throw new Error('ADMIN_PASSWORD debe tener al menos 10 caracteres');await pool.query("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'admin')",[username,await bcrypt.hash(process.env.ADMIN_PASSWORD,12)]);console.log('Administrador inicial creado');}
 }
 app.listen(process.env.PORT||3000,()=>console.log('Rifa solidaria en puerto '+(process.env.PORT||3000)));
}
start().catch(e=>{console.error(e);process.exit(1)});
