ALTER TABLE owner ADD COLUMN auth_generation INTEGER NOT NULL DEFAULT 1;
CREATE TABLE login_limits (
 key TEXT PRIMARY KEY,
 admission TEXT NOT NULL DEFAULT '',
 failures INTEGER NOT NULL DEFAULT 0,
 window_start INTEGER NOT NULL,
 blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX login_limits_expiry ON login_limits(window_start);
CREATE TABLE helper_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL);
