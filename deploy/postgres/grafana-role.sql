-- Read-only role for Grafana, applied by deploy.sh on every deploy (idempotent).
-- Piped to psql with `\set pw '<password>'` prepended; the password never appears in argv.
-- Only the tables dashboards need; no access to credentials or session reports.
SELECT format('CREATE ROLE grafana_ro LOGIN PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_ro') \gexec
SELECT format('ALTER ROLE grafana_ro PASSWORD %L', :'pw') \gexec
ALTER ROLE grafana_ro SET default_transaction_read_only = on;
ALTER ROLE grafana_ro SET statement_timeout = '10s';
GRANT CONNECT ON DATABASE mirage TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON requests, sessions, detections TO grafana_ro;
