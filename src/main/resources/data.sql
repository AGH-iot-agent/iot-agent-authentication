INSERT INTO users (username, password_hash, email) VALUES ('test', '$2a$10$wqQwQwQwQwQwQwQwQwQwQeQwQwQwQwQwQwQwQwQwQwQwQwQwQwQ', 'test@example.com') ON CONFLICT DO NOTHING;
-- Hasło: test (bcrypt hash, do zmiany w realnym środowisku)
