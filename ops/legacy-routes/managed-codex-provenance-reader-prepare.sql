\set ON_ERROR_STOP on

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15000';
SELECT set_config('mtc.managed_codex_reader_mode', :'reader_mode', true);
SELECT set_config('mtc.managed_codex_reader_valid_until', :'reader_valid_until', true);

DO $prepare$
DECLARE
  reader_role constant name := 'provenance_codex_reader_v1';
  reader_comment constant text := 'one-shot managed Codex provenance reader v1';
  target_relations constant regclass[] := ARRAY[
    'public.tenants'::regclass,
    'public.upstream_account_imports'::regclass,
    'public.upstream_accounts'::regclass,
    'public.upstream_credentials'::regclass
  ];
  requested_mode text := current_setting('mtc.managed_codex_reader_mode', true);
  requested_valid_until timestamptz := current_setting('mtc.managed_codex_reader_valid_until', true)::timestamptz;
  reader_role_id oid;
  role_record record;
BEGIN
  IF current_database() <> 'memeloop_token_center' THEN
    RAISE EXCEPTION 'managed Codex provenance reader preparation is fenced to memeloop_token_center';
  END IF;
  IF requested_mode IS NULL OR requested_mode NOT IN ('direct', 'cnpg') THEN
    RAISE EXCEPTION 'reader_mode must be direct or cnpg';
  END IF;
  IF requested_valid_until IS NULL
     OR requested_valid_until <= clock_timestamp()
     OR requested_valid_until > clock_timestamp() + interval '4 hours' THEN
    RAISE EXCEPTION 'reader_valid_until must be in the future and no more than four hours away';
  END IF;

  IF requested_mode = 'direct' THEN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = reader_role) THEN
      RAISE EXCEPTION 'managed Codex provenance reader role already exists; refusing to adopt, alter, drop, or recreate it';
    END IF;
    EXECUTE format(
      'CREATE ROLE %I NOLOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOSUPERUSER CONNECTION LIMIT 1 VALID UNTIL %L',
      reader_role,
      requested_valid_until
    );
    EXECUTE format('COMMENT ON ROLE %I IS %L', reader_role, reader_comment);
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
         catalog_role.rolvaliduntil,
         shobj_description(catalog_role.oid, 'pg_authid') AS comment
    INTO role_record
    FROM pg_roles AS catalog_role
   WHERE catalog_role.rolname = reader_role;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'managed Codex provenance reader role is absent; create it through the approved CNPG declaration before cnpg preparation';
  END IF;
  reader_role_id := role_record.oid;
  IF role_record.rolsuper
     OR role_record.rolcreatedb
     OR role_record.rolcreaterole
     OR role_record.rolreplication
     OR role_record.rolbypassrls
     OR role_record.rolinherit
     OR role_record.rolconnlimit <> 1
     OR role_record.rolvaliduntil IS DISTINCT FROM requested_valid_until
     OR role_record.comment IS DISTINCT FROM reader_comment
     OR (requested_mode = 'direct' AND role_record.rolcanlogin)
     OR (requested_mode = 'cnpg' AND NOT role_record.rolcanlogin) THEN
    RAISE EXCEPTION 'managed Codex provenance reader role does not match the exact one-shot contract';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_auth_members AS membership
     WHERE membership.roleid = reader_role_id OR membership.member = reader_role_id
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader role has unexpected role membership';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_shdepend AS dependency
     WHERE dependency.refclassid = 'pg_authid'::regclass
       AND dependency.refobjid = reader_role_id
       AND dependency.deptype = 'o'
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader role owns an object and cannot be used';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_class AS relation
      CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege
     WHERE relation.oid = ANY (target_relations)
       AND privilege.grantee IN (0, reader_role_id)
  ) OR EXISTS (
    SELECT 1
      FROM pg_attribute AS column_record
      CROSS JOIN LATERAL aclexplode(COALESCE(column_record.attacl, '{}'::aclitem[])) AS privilege
     WHERE column_record.attrelid = ANY (target_relations)
       AND column_record.attnum > 0
       AND NOT column_record.attisdropped
       AND privilege.grantee IN (0, reader_role_id)
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader or PUBLIC already has relation privileges; refusing to grant';
  END IF;
END;
$prepare$;

GRANT CONNECT ON DATABASE memeloop_token_center TO provenance_codex_reader_v1;
GRANT USAGE ON SCHEMA public TO provenance_codex_reader_v1;
GRANT SELECT (id, external_id)
  ON TABLE public.tenants
  TO provenance_codex_reader_v1;
GRANT SELECT (tenant_id, import_kind, source_key, payload_digest, contract_version, upstream_account_id)
  ON TABLE public.upstream_account_imports
  TO provenance_codex_reader_v1;
GRANT SELECT (id, tenant_id, driver, auth_kind, status, credential_generation, oauth_session_id, oauth_driver, oauth_refresh_url, updated_at)
  ON TABLE public.upstream_accounts
  TO provenance_codex_reader_v1;
GRANT SELECT (upstream_account_id, generation, revoked_at)
  ON TABLE public.upstream_credentials
  TO provenance_codex_reader_v1;

DO $verify$
DECLARE
  reader_role constant name := 'provenance_codex_reader_v1';
  reader_role_id oid;
  target_relations constant regclass[] := ARRAY[
    'public.tenants'::regclass,
    'public.upstream_account_imports'::regclass,
    'public.upstream_accounts'::regclass,
    'public.upstream_credentials'::regclass
  ];
BEGIN
  SELECT oid INTO reader_role_id FROM pg_roles WHERE rolname = reader_role;
  IF reader_role_id IS NULL THEN
    RAISE EXCEPTION 'managed Codex provenance reader role disappeared during preparation';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_class AS relation
      CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege
     WHERE relation.oid = ANY (target_relations)
       AND privilege.grantee = reader_role_id
  ) OR EXISTS (
    SELECT 1
      FROM pg_attribute AS column_record
      CROSS JOIN LATERAL aclexplode(COALESCE(column_record.attacl, '{}'::aclitem[])) AS privilege
     WHERE column_record.attrelid = ANY (target_relations)
       AND column_record.attnum > 0
       AND NOT column_record.attisdropped
       AND privilege.grantee = reader_role_id
       AND (
         privilege.privilege_type <> 'SELECT'
         OR NOT (
           (column_record.attrelid = 'public.tenants'::regclass
             AND column_record.attname IN ('id', 'external_id'))
           OR (column_record.attrelid = 'public.upstream_account_imports'::regclass
             AND column_record.attname IN ('tenant_id', 'import_kind', 'source_key', 'payload_digest', 'contract_version', 'upstream_account_id'))
           OR (column_record.attrelid = 'public.upstream_accounts'::regclass
             AND column_record.attname IN ('id', 'tenant_id', 'driver', 'auth_kind', 'status', 'credential_generation', 'oauth_session_id', 'oauth_driver', 'oauth_refresh_url', 'updated_at'))
           OR (column_record.attrelid = 'public.upstream_credentials'::regclass
             AND column_record.attname IN ('upstream_account_id', 'generation', 'revoked_at'))
         )
       )
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader has a privilege outside its fixed column contract';
  END IF;
  IF NOT has_column_privilege(reader_role, 'public.tenants', 'id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.tenants', 'external_id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_account_imports', 'tenant_id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_account_imports', 'import_kind', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_account_imports', 'source_key', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_account_imports', 'payload_digest', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_account_imports', 'contract_version', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_account_imports', 'upstream_account_id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'tenant_id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'driver', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'auth_kind', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'status', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'credential_generation', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'oauth_session_id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'oauth_driver', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'oauth_refresh_url', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_accounts', 'updated_at', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_credentials', 'upstream_account_id', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_credentials', 'generation', 'SELECT')
     OR NOT has_column_privilege(reader_role, 'public.upstream_credentials', 'revoked_at', 'SELECT')
     OR has_column_privilege(reader_role, 'public.upstream_credentials', 'credential_ciphertext', 'SELECT') THEN
    RAISE EXCEPTION 'managed Codex provenance reader column privileges are incomplete or expose credential ciphertext';
  END IF;
END;
$verify$;

COMMIT;
