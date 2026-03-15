-- intentionally public demo dump
CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR(255), password VARCHAR(255));
INSERT INTO users VALUES (1, 'admin@example.com', '$2y$12$demo.hash.value');
