-- Store emails in normalized form (trimmed, lower-case).
-- No WHERE clause: under the default case-insensitive collation 'Ada@x.com' <> 'ada@x.com'
-- is false, so a comparison would skip the rows that need rewriting.
-- Fails on the users.email unique constraint if two users differ only in surrounding
-- whitespace; merge or rename those users before migrating.
UPDATE users SET email = LOWER(TRIM(email));
