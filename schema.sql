CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY,
 username VARCHAR(60) NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role VARCHAR(12) NOT NULL CHECK (role IN ('admin','seller')),
 active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tickets (
 letter CHAR(1) NOT NULL CHECK (letter BETWEEN 'A' AND 'Z'),
 number SMALLINT NOT NULL CHECK (number BETWEEN 1 AND 100),
 status VARCHAR(12) NOT NULL DEFAULT 'available' CHECK (status IN ('available','reserved','paid')),
 buyer_name VARCHAR(120),
 buyer_phone VARCHAR(40),
 seller_id BIGINT REFERENCES users(id),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(letter,number),
 CONSTRAINT ticket_fields CHECK (
 (status='available' AND buyer_name IS NULL AND buyer_phone IS NULL AND seller_id IS NULL)
 OR (status IN ('reserved','paid') AND buyer_name IS NOT NULL AND buyer_phone IS NOT NULL AND seller_id IS NOT NULL)
 )
);
CREATE TABLE IF NOT EXISTS audit_log (
 id BIGSERIAL PRIMARY KEY,
 letter CHAR(1) NOT NULL,
 number SMALLINT NOT NULL,
 actor_id BIGINT REFERENCES users(id),
 action VARCHAR(20) NOT NULL,
 previous_status VARCHAR(12) NOT NULL,
 new_status VARCHAR(12) NOT NULL,
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO tickets(letter,number)
SELECT chr(l)::char(1), n FROM generate_series(65,90) AS l CROSS JOIN generate_series(1,100) AS n
ON CONFLICT DO NOTHING;

-- v1.1: migración aditiva, conserva todos los tickets y usuarios.
CREATE TABLE IF NOT EXISTS physical_letters (
 letter CHAR(1) PRIMARY KEY CHECK (letter BETWEEN 'A' AND 'Z'),
 responsible VARCHAR(120) NOT NULL,
 created_by BIGINT REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS cancellation_details (
 id BIGSERIAL PRIMARY KEY, letter CHAR(1) NOT NULL, number SMALLINT NOT NULL,
 buyer_name VARCHAR(120) NOT NULL, buyer_phone VARCHAR(40) NOT NULL,
 seller_id BIGINT REFERENCES users(id), cancelled_by BIGINT REFERENCES users(id),
 reason TEXT NOT NULL, refund_state VARCHAR(24) NOT NULL,
 cancelled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
