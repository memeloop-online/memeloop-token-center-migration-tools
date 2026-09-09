\set ON_ERROR_STOP on

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '15000';

DO $preflight$
DECLARE
  reader_role constant name := 'mtc_managed_codex_provenance_reader_v1';
  target_relations constant regclass[] := ARRAY[
    'public.tenants'::regclass,
    'public.upstream_account_imports'::regclass,
    'public.upstream_accounts'::regclass,
    'public.upstream_credentials'::regclass
  ];
BEGIN
  IF current_database() <> 'memeloop_token_center' THEN
    RAISE EXCEPTION 'managed Codex provenance reader preflight is fenced to memeloop_token_center';
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = reader_role) THEN
    RAISE EXCEPTION 'managed Codex provenance reader role already exists; refusing to adopt, alter, drop, or recreate it';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM unnest(target_relations) AS relation_oid
     WHERE relation_oid IS NULL
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader relation inventory is incomplete';
  END IF;

  -- Any PUBLIC grant would bypass this new role's column-level boundary.
  IF EXISTS (
    SELECT 1
      FROM pg_class relation
      CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege
     WHERE relation.oid = ANY (target_relations)
       AND privilege.grantee = 0
  ) OR EXISTS (
    SELECT 1
      FROM pg_attribute column_record
      CROSS JOIN LATERAL aclexplode(COALESCE(column_record.attacl, '{}'::aclitem[])) AS privilege
     WHERE column_record.attrelid = ANY (target_relations)
       AND column_record.attnum > 0
       AND NOT column_record.attisdropped
       AND privilege.grantee = 0
  ) THEN
    RAISE EXCEPTION 'managed Codex provenance reader preflight found PUBLIC privileges on a protected relation';
  END IF;
END;
$preflight$;

COMMIT;
