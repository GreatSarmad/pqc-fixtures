-- Probe: store a post-quantum certificate chain in the kind of column schemas
-- actually declare for certificates, and see which statements survive.
--
-- Two limits bite, and neither is obvious from a migration file:
--
--   1. A hand-picked VARCHAR(n). Nobody measures a certificate before choosing
--      n; 4096 is the folk default and comfortably fits anything RSA produces.
--   2. PostgreSQL's btree index row limit. Indexing a certificate column is
--      common (dedupe, lookup by PEM) and works fine until the certificates
--      grow. Measured against PostgreSQL 17, a 23 KB chain is refused with
--      "index row requires 23104 bytes, maximum size is 8191".
--
-- Run with:
--   psql -X -v chain=/path/to/INSECURE-TEST-fullchain.pem -f postgres-cert-column.sql
--
-- Every statement below runs in its own implicit transaction, deliberately:
-- inside one explicit BEGIN, the first expected failure would abort the
-- transaction and every later statement would report "current transaction is
-- aborted" instead of its own result. Each statement has to be allowed to fail
-- on its own terms.

\set ON_ERROR_STOP 0

DROP TABLE IF EXISTS pqc_probe_cert;

CREATE TABLE pqc_probe_cert (
    id        serial PRIMARY KEY,
    -- The folk default: wide enough for any classical certificate.
    pem_4096  varchar(4096),
    -- What the column should have been all along.
    pem_text  text
);

-- Read the fixture chain into a psql variable. :chain is supplied with -v.
\set chain_pem `cat :chain`

\echo ''
\echo '  measuring the chain'
SELECT
    length(:'chain_pem')        AS chain_bytes,
    4096                        AS varchar_limit,
    length(:'chain_pem') - 4096 AS bytes_over_varchar;

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

DROP TABLE IF EXISTS pqc_probe_cert;

\echo ''
\echo '  Statements 1 and 3 are expected to fail on a post-quantum chain and to'
\echo '  succeed on a classical one. Statement 4 needs pgcrypto; if it errors'
\echo '  with "function digest does not exist", that is a missing extension,'
\echo '  not a size limit.'
