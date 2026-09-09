\set ON_ERROR_STOP on

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15000';

DO $cleanup_preflight$
DECLARE
  reader_role constant name := 'provenance_codex_reader_v1';
  reader_comment constant text := 'one-shot managed Codex provenance reader v1';
  reader_role_id oid;
  role_record record;
BEGIN
  IF current_database() <> 'memeloop_token_center' THEN
    RAISE EXCEPTION 'managed Codex provenance reader cleanup is fenced to memeloop_token_center';
  END IF;

  SELECT catalog_role.oid,
         catalog_role.rolcanlogin,
         catalog_role.rolsuper,
         catalog_role.rolcreatedb,
         catalog_role.rolcreaterole,
         catalog_role.rolreplication,
         catalog_role.rolbypassrls,
         catalog_role.rolinherit,
         catalog_role.rolconnlimit,
         shobj_description(catalog_role.oid, 'pg_authid') AS comment
    INTO role_record
    FROM pg_roles AS catalog_role
   WHERE catalog_role.rolname = reader_role;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'managed Codex provenance reader role is absent; refusing to recreate it during cleanup';
  END IF;
  reader_role_id := role_record.oid;
  IF role_record.rolcanlogin
     OR role_record.rolsuper
     OR role_record.rolcreatedb
     OR role_record.rolcreaterole
     OR role_record.rolreplication
     OR role_record.rolbypassrls
     OR role_record.rolinherit
     OR role_record.rolconnlimit <> 1
     OR role_record.comment IS DISTINCT FROM reader_comment THEN
    RAISE EXCEPTION 'managed Codex provenance reader role does not match the cleanup contract; refusing to adopt or drop it';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_auth_members AS membership
     WHERE membership.roleid = reader_role_id OR membership.member = reader_role_id
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader role has unexpected role membership; refusing to drop it';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_shdepend AS dependency
     WHERE dependency.refclassid = 'pg_authid'::regclass
       AND dependency.refobjid = reader_role_id
       AND dependency.deptype = 'o'
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader role owns an object; refusing to drop it';
  END IF;
END;
$cleanup_preflight$;

REVOKE SELECT (id, external_id)
  ON TABLE public.tenants
  FROM provenance_codex_reader_v1;
REVOKE SELECT (tenant_id, import_kind, source_key, payload_digest, contract_version, upstream_account_id)
  ON TABLE public.upstream_account_imports
  FROM provenance_codex_reader_v1;
REVOKE SELECT (id, tenant_id, driver, auth_kind, status, credential_generation, oauth_session_id, oauth_driver, oauth_refresh_url, updated_at)
  ON TABLE public.upstream_accounts
  FROM provenance_codex_reader_v1;
REVOKE SELECT (upstream_account_id, generation, revoked_at)
  ON TABLE public.upstream_credentials
  FROM provenance_codex_reader_v1;
REVOKE USAGE ON SCHEMA public FROM provenance_codex_reader_v1;
REVOKE CONNECT ON DATABASE memeloop_token_center FROM provenance_codex_reader_v1;
DROP ROLE provenance_codex_reader_v1;

COMMIT;
