INSERT INTO users (username, password_hash, email)
VALUES ('admin', '$2b$10$Io1vrrLw6CCe4JAOniGT5O9Kx5Gq25MLTDWhLauPDwbl.6x/mB0lO', 'admin@iotag.local')
ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, email = EXCLUDED.email;
-- Hasło: admin123
