-- Store emails in normalized form (trimmed, lower-case) so lookups are case-insensitive.
-- SQLite's LOWER() only folds ASCII letters.
-- Fails on the users.email unique constraint if two users differ only in email case or
-- whitespace; merge or rename those users before migrating.
UPDATE users SET email = LOWER(TRIM(email)) WHERE email <> LOWER(TRIM(email));
