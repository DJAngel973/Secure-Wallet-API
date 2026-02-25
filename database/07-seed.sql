-- TEST DATA (DEVELOPMENT ONLY)

-- Test user (password: Test1234!)
INSERT INTO users (email, password_hash, role, email_verified) VALUES
('admin@test.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye1J8FRKp0LEzKd6KPXB5z.Q7.QN0lLBa', 'ADMIN', TRUE),
('user@test.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye1J8FRKp0LEzKd6KPXB5z.Q7.QN0lLBa', 'USER', TRUE);

-- Test wallets
INSERT INTO wallets (user_id, balance, currency) VALUES
((SELECT id FROM users WHERE email = 'admin@test.com'), 1000.00, 'USD'),
((SELECT id FROM users WHERE email = 'user@test.com'), 500.00, 'USD');

-- Test log
INSERT INTO audit_logs (user_id, action, severity_level, details) VALUES
((SELECT id FROM users WHERE email = 'admin@test.com'), 'USER_LOGIN', 'INFO', '{"ip": "127.0.0.1"}');