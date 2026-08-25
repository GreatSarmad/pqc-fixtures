-- Probe: store a post-quantum certificate chain in the kind of column schemas
-- actually declare for certificates, and see which statements survive.
--
-- Two limits bite, and neither is obvious from a migration file:
--
--   1. A hand-picked VARCHAR(n). Nobody measures a certificate before choosing
--      n; 4096 is the folk default and comfortably fits anything RSA produces.
--   2. PostgreSQL's btree index row limit — about 2704 bytes, a third of a
--      page. Indexing a certificate column is common (dedupe, lookup by PEM)
--      and works fine until the certificates grow.
--
-- Run with:
--   psql -v chain=/path/to/INSECURE-TEST-fullchain.pem -f postgres-cert-column.sql
--
-- Every failing statement below is expected to fail. ON_ERROR_STOP must be off
-- so the script reports all of them rather than the first.

\set ON_ERROR_STOP 0
\set QUIET 1

BEGIN;

CREATE TEMPORARY TABLE pqc_probe_cert (
    id        serial PRIMARY KEY,
    -- The folk default: wide enough for any classical certificate.
    pem_4096  varchar(4096),
    -- What the column should have been all along.
    pem_text  text
) ON COMMIT DROP;

-- Read the fixture chain into a psql variable. :chain is supplied with -v.
\set chain_pem `cat :chain`

\echo '  measuring the chain'
SELECT
    length(:'chain_pem')                             AS chain_bytes,
    4096                                             AS varchar_limit,
    length(:'chain_pem') - 4096                      AS bytes_over_varchar,
    2704                                             AS btree_row_limit;

\echo ''
\echo '  1. INSERT into varchar(4096) — the folk default'
INSERT INTO pqc_probe_cert (pem_4096) VALUES (:'chain_pem');

\echo ''
\echo '  2. INSERT into text — no declared width'
INSERT INTO pqc_probe_cert (pem_text) VALUES (:'chain_pem');

\echo ''
\echo '  3. CREATE INDEX on the text column — btree row limit'
CREATE INDEX pqc_probe_cert_pem_idx ON pqc_probe_cert (pem_text);

\echo ''
\echo '  4. CREATE INDEX on a hash of the column — the fix'
CREATE INDEX pqc_probe_cert_pem_sha_idx ON pqc_probe_cert (digest(pem_text, 'sha256'));

\echo ''
\echo '  rows that made it in:'
SELECT
    id,
    length(pem_4096) AS varchar_len,
    length(pem_text) AS text_len
FROM pqc_probe_cert
ORDER BY id;

COMMIT;

\echo ''
\echo '  Statements 1 and 3 are expected to fail on a post-quantum chain and to'
\echo '  succeed on a classical one. Statement 4 needs pgcrypto; if it errors'
\echo '  with "function digest does not exist", that is a missing extension,'
\echo '  not a size limit.'
