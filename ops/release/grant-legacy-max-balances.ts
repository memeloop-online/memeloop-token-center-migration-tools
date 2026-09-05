import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

const moneyScale = 1_000_000n;
export const maximumBalanceMicros = 9_223_372_036_854_775_807n;

type ManagedKey = Readonly<{
  account_id: string;
  available_balance: string;
  tenant_external_id: string;
}>;

type GrantOptions = Readonly<{
  baseUrl: string;
  serviceToken: string;
  tenantExternalId: string;
  accountIds: readonly string[];
  fetchImpl?: typeof fetch;
  attempts?: number;
  operationId?: string;
}>;

function decimalToMicros(value: string): bigint {
  const match = /^(\d+)(?:\.(\d{1,6}))?$/.exec(value);
  if (!match) throw new Error("managed key returned an invalid balance");
  return BigInt(match[1]!) * moneyScale + BigInt((match[2] ?? "").padEnd(6, "0"));
}

function microsToDecimal(value: bigint): string {
  const whole = value / moneyScale;
  const fraction = (value % moneyScale).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction.length === 0 ? whole.toString() : `${whole}.${fraction}`;
}

async function requestWithRetry(
  request: () => Promise<Response>,
  attempts: number,
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await request();
      if (response.ok) return response;
      const body = await response.text();
      lastError = new Error(`HTTP ${response.status}: ${body.slice(0, 500)}`);
      if (response.status < 500 && response.status !== 429) break;
    } catch (error) {
      lastError = error;
    }
    if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, attempt * 250));
  }
  throw lastError instanceof Error ? lastError : new Error("request failed");
}

export async function grantLegacyMaximumBalances(options: GrantOptions): Promise<{
  accounts: number;
  grantsCreated: number;
  alreadyMaximum: number;
}> {
  const fetcher = options.fetchImpl ?? fetch;
  const attempts = options.attempts ?? 5;
  if (attempts < 1 || attempts > 5) throw new Error("attempts must be between 1 and 5");
  const operationId = options.operationId ?? randomUUID();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(operationId)) throw new Error("operation ID is invalid");
  const accountIds = new Set(options.accountIds);
  if (accountIds.size === 0 || accountIds.size !== options.accountIds.length) {
    throw new Error("legacy account IDs must be non-empty and unique");
  }
  const headers = { authorization: `Bearer ${options.serviceToken}` };
  const listUrl = new URL("/internal/v1/keys", options.baseUrl);
  listUrl.searchParams.set("tenant_external_id", options.tenantExternalId);
  listUrl.searchParams.set("limit", "500");
  const list = async (): Promise<ManagedKey[]> => {
    const response = await requestWithRetry(
      () => fetcher(listUrl, { headers, signal: AbortSignal.timeout(30_000) }),
      attempts,
    );
    return await response.json() as ManagedKey[];
  };
  const exactInventory = async (): Promise<ManagedKey[]> => {
    const keys = (await list()).filter((key) => accountIds.has(key.account_id));
    if (keys.length !== accountIds.size || keys.some((key) => key.tenant_external_id !== options.tenantExternalId)) {
      throw new Error("legacy account inventory does not exactly match the target tenant");
    }
    return keys;
  };

  let grantsCreated = 0;
  let alreadyMaximum = 0;
  for (let round = 1; round <= attempts; round += 1) {
    const currentKeys = await exactInventory();
    const pending: Array<{ key: ManagedKey; current: bigint }> = [];
    for (const key of currentKeys) {
      const current = decimalToMicros(key.available_balance);
      if (current > maximumBalanceMicros) throw new Error("balance exceeds the monetary range");
      if (current === maximumBalanceMicros) {
        if (round === 1) alreadyMaximum += 1;
      } else {
        pending.push({ key, current });
      }
    }
    if (pending.length === 0) return { accounts: accountIds.size, grantsCreated, alreadyMaximum };
    for (const { key, current } of pending) {
      const delta = maximumBalanceMicros - current;
      const url = new URL(`/internal/v1/accounts/${encodeURIComponent(key.account_id)}/grants`, options.baseUrl);
      await requestWithRetry(
        () => fetcher(url, {
          method: "POST",
          headers: {
            ...headers,
            "content-type": "application/json",
            // Bind replay identity to the observed starting balance. A later
            // billable probe therefore creates a new exact operation instead
            // of replaying an older, larger grant with a different payload.
            "idempotency-key": `legacy-max-balance-v3-${operationId}-${round}-${key.account_id}-${current}`,
          },
          body: JSON.stringify({ amount: microsToDecimal(delta), source: "legacy-cpa-production-cutover" }),
          signal: AbortSignal.timeout(30_000),
        }),
        attempts,
      );
      grantsCreated += 1;
    }
    const after = await exactInventory();
    if (after.every((key) => decimalToMicros(key.available_balance) === maximumBalanceMicros)) {
      return { accounts: accountIds.size, grantsCreated, alreadyMaximum };
    }
  }
  throw new Error("post-grant balance fence did not converge within the retry boundary");
}

async function main(): Promise<void> {
  const baseUrl = process.env.MTC_CONTROL_BASE_URL ?? "http://127.0.0.1:18081";
  const serviceToken = process.env.MTC_SERVICE_TOKEN ?? "";
  const tenantExternalId = process.env.MTC_TENANT_EXTERNAL_ID ?? "cpa-dogfood-import";
  const accountIds = (process.env.MTC_LEGACY_ACCOUNT_IDS ?? "").split(/\s+/).filter(Boolean);
  if (!serviceToken) throw new Error("MTC_SERVICE_TOKEN is required");
  const result = await grantLegacyMaximumBalances({ baseUrl, serviceToken, tenantExternalId, accountIds });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
