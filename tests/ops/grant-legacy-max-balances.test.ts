import assert from "node:assert/strict";
import { test } from "node:test";

import {
  grantLegacyMaximumBalances,
  maximumBalanceMicros,
} from "../../ops/release/grant-legacy-max-balances.ts";

test("grants each legacy account to the maximum and replays without a second grant", async () => {
  const balances = new Map([["account-a", 0n], ["account-b", 1_000_000n]]);
  const idempotency = new Map<string, bigint>();
  const calls: string[] = [];
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    if (init?.method !== "POST") {
      return Response.json([...balances].map(([account_id, balance]) => ({
        account_id,
        tenant_external_id: "legacy",
        available_balance: `${balance / 1_000_000n}.${(balance % 1_000_000n).toString().padStart(6, "0")}`,
      })));
    }
    const account = url.pathname.split("/").at(-2) ?? "";
    const key = new Headers(init.headers).get("idempotency-key") ?? "";
    const amount = (JSON.parse(String(init.body)) as { amount: string }).amount;
    const [whole, fraction = ""] = amount.split(".");
    const micros = BigInt(whole!) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
    if (!idempotency.has(key)) {
      balances.set(account, (balances.get(account) ?? 0n) + micros);
      idempotency.set(key, micros);
      calls.push(account);
    }
    return Response.json({ granted: amount }, { status: 201 });
  };

  const options = {
    baseUrl: "http://control.test",
    serviceToken: "secret",
    tenantExternalId: "legacy",
    accountIds: ["account-a", "account-b"],
    fetchImpl: fetchImpl as typeof fetch,
    operationId: "first-run",
  };
  assert.deepEqual(await grantLegacyMaximumBalances(options), { accounts: 2, grantsCreated: 2, alreadyMaximum: 0 });
  assert.deepEqual(await grantLegacyMaximumBalances({ ...options, operationId: "replay-run" }), { accounts: 2, grantsCreated: 0, alreadyMaximum: 2 });
  assert.deepEqual(calls, ["account-a", "account-b"]);
  assert.ok([...balances.values()].every((balance) => balance === maximumBalanceMicros));
});

test("uses a new exact grant after billable work races the first balance fence", async () => {
  const balances = new Map([["account-a", 0n]]);
  const idempotency = new Map<string, bigint>();
  let charged = false;
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    if (init?.method !== "POST") {
      const balance = balances.get("account-a")!;
      return Response.json([{
        account_id: "account-a",
        tenant_external_id: "legacy",
        available_balance: `${balance / 1_000_000n}.${(balance % 1_000_000n).toString().padStart(6, "0")}`,
      }]);
    }
    const key = new Headers(init.headers).get("idempotency-key") ?? "";
    const amount = (JSON.parse(String(init.body)) as { amount: string }).amount;
    const [whole, fraction = ""] = amount.split(".");
    const micros = BigInt(whole!) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
    if (!idempotency.has(key)) {
      balances.set("account-a", balances.get("account-a")! + micros);
      idempotency.set(key, micros);
      if (!charged) {
        balances.set("account-a", balances.get("account-a")! - 781n);
        charged = true;
      }
    }
    assert.equal(url.pathname, "/internal/v1/accounts/account-a/grants");
    return Response.json({ granted: amount }, { status: 201 });
  };

  assert.deepEqual(await grantLegacyMaximumBalances({
    baseUrl: "http://control.test",
    serviceToken: "secret",
    tenantExternalId: "legacy",
    accountIds: ["account-a"],
    fetchImpl: fetchImpl as typeof fetch,
    operationId: "race-run",
  }), { accounts: 1, grantsCreated: 2, alreadyMaximum: 0 });
  assert.equal(balances.get("account-a"), maximumBalanceMicros);
  assert.equal(idempotency.size, 2);
});

test("the fifth grant round still receives a final read fence", async () => {
  let balance = 0n;
  let grantCount = 0;
  const fetchImpl = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    if (init?.method !== "POST") {
      return Response.json([{
        account_id: "account-a",
        tenant_external_id: "legacy",
        available_balance: `${balance / 1_000_000n}.${(balance % 1_000_000n).toString().padStart(6, "0")}`,
      }]);
    }
    const amount = (JSON.parse(String(init.body)) as { amount: string }).amount;
    const [whole, fraction = ""] = amount.split(".");
    balance += BigInt(whole!) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
    grantCount += 1;
    if (grantCount < 5) balance -= 1n;
    return Response.json({ granted: amount }, { status: 201 });
  };
  const result = await grantLegacyMaximumBalances({
    baseUrl: "http://control.test",
    serviceToken: "secret",
    tenantExternalId: "legacy",
    accountIds: ["account-a"],
    fetchImpl: fetchImpl as typeof fetch,
    attempts: 5,
    operationId: "fifth-round",
  });
  assert.deepEqual(result, { accounts: 1, grantsCreated: 5, alreadyMaximum: 0 });
  assert.equal(balance, maximumBalanceMicros);
});
