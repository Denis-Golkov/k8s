
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    user_name VARCHAR (50) UNIQUE,
    password VARCHAR (50)
);


CREATE TABLE IF NOT EXISTS domains (
    domain_id SERIAL PRIMARY KEY,
    domain VARCHAR(100), 
    status VARCHAR(100),
    ssl_expiration VARCHAR(100),
    ssl_issuer VARCHAR(100)
);


CREATE TABLE IF NOT EXISTS  relation(
    user_id INT REFERENCES users(user_id),
    domain_id INT REFERENCES domains(domain_id) 
);
