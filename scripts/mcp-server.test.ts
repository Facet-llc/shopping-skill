// mcp-server.test.ts
// Tests for the MCP wrapper. They prove three things:
//   1. The stdio transport answers initialize and tools/list, and the buyer tool
//      surface is present on the wire.
//   2. A tools/call that loads the wallet key (facet_wallet_list) returns the
//      public address and balance but never the private key or mnemonic, driven
//      against a mocked RPC so it needs no real network.
//   3. The child runner discards child stderr, so a secret a child writes there
//      can never reach a tool result.

import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@^1";
import {
  executeTool,
  handleMessage,
  normalizeExchangeIds,
  perLineBodyKey,
  planPerLineEscrowAction,
  spawnCaptureStdout,
  TOOLS,
} from "./mcp-server.ts";
import { addressFromPrivateKey, mintWallet } from "./wallet.ts";

const EXPECTED_TOOLS = [
  "facet_wallet_list",
  "facet_wallet_new",
  "facet_fund",
  "facet_provision",
  "facet_discover",
  "facet_directory",
  "facet_search",
  "facet_product",
  "facet_buy",
  "facet_mpp_charge",
  "facet_email_pref",
  "facet_browse_storefront",
  "facet_redeem",
  "facet_cancel",
  "facet_withdraw",
  "facet_dispute",
  "facet_lines",
  "facet_refund",
  "facet_resolve",
  "facet_reorder",
  "facet_revise",
  "facet_get_receipt",
  "facet_render_receipt",
  "facet_lifecycle_receipt",
  "facet_receipts",
  "facet_version",
];

const SCRIPT_DIR = new URL(".", import.meta.url).pathname;
// The forbidden em and en dash codepoints, referenced without writing the literal
// characters (they are barred from source everywhere).
const DASHES = String.fromCharCode(0x2014) + String.fromCharCode(0x2013);

// ---- 1. stdio transport: initialize + tools/list ---------------------------

Deno.test("stdio transport lists the buyer tool surface", async () => {
  const child = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-env",
      "--allow-read",
      "--allow-run",
      `${SCRIPT_DIR}mcp-server.ts`,
    ],
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
  }).spawn();

  const enc = new TextEncoder();
  const writer = child.stdin.getWriter();
  await writer.write(
    enc.encode(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "test", version: "0" },
        },
      }) + "\n",
    ),
  );
  await writer.write(
    enc.encode(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n"),
  );
  await writer.close();

  const out = await new Response(child.stdout).text();
  await child.status;

  const responses = out
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));

  const init = responses.find((r) => r.id === 1);
  assert(init !== undefined, "no initialize response");
  assertEquals(init.result.serverInfo.name, "facet-shopping");
  assert(init.result.capabilities.tools !== undefined, "no tools capability advertised");

  const list = responses.find((r) => r.id === 2);
  assert(list !== undefined, "no tools/list response");
  const tools = list.result.tools as Array<{ name: string; inputSchema: unknown }>;
  const names = tools.map((t) => t.name);
  for (const expected of EXPECTED_TOOLS) {
    assert(names.includes(expected), `tools/list is missing ${expected}`);
  }
  // Every advertised tool carries an input schema.
  for (const t of tools) {
    assert(t.inputSchema !== undefined, "a tool is missing inputSchema");
  }
});

// ---- 2. tools/call never returns a wallet secret ---------------------------

Deno.test("tools/call facet_wallet_list returns the address, never the key", async () => {
  // A fresh, unfunded throwaway wallet. Both the mnemonic and the private key are
  // secrets that must never appear in a tool result.
  const wallet = mintWallet();
  const derived = addressFromPrivateKey(wallet.privateKey);

  // Mock the USDC RPC: answer any eth_call with a fixed 5 USDC balance.
  const balanceHex = "0x" + (5_000_000).toString(16).padStart(64, "0");
  const rpc = Deno.serve(
    { port: 0, onListen: () => {} },
    () =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: balanceHex }), {
        headers: { "content-type": "application/json" },
      }),
  );
  const rpcUrl = `http://127.0.0.1:${rpc.addr.port}`;

  const tmpHome = await Deno.makeTempDir({ prefix: "facet-mcp-test-" });
  const saved: Record<string, string | undefined> = {};
  const setEnv = (k: string, v: string | undefined) => {
    saved[k] = Deno.env.get(k);
    if (v === undefined) Deno.env.delete(k);
    else Deno.env.set(k, v);
  };

  try {
    setEnv("HOME", tmpHome);
    setEnv("FACET_WALLET_KEY", wallet.privateKey);
    setEnv("FACET_RPC", rpcUrl);
    setEnv("FACET_WALLETS", undefined);
    setEnv("FACET_KYA", undefined);

    // Drive it through the JSON-RPC dispatch, exactly as a client's tools/call would.
    const response = await handleMessage({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "facet_wallet_list", arguments: {} },
    });
    assert(response !== null, "tools/call returned no response");

    const result = response.result as { content: Array<{ text: string }>; isError: boolean };
    const text = result.content[0].text;
    const payload = JSON.parse(text) as {
      ok: boolean;
      wallets: Array<{ address: string; usdc_balance: number; kya_present: boolean }>;
    };

    // The happy path returns the public facts.
    assertEquals(result.isError, false);
    assertEquals(payload.ok, true);
    assertEquals(payload.wallets[0].address, derived);
    assertEquals(payload.wallets[0].usdc_balance, 5);
    assertEquals(payload.wallets[0].kya_present, false);

    // The invariant: neither secret appears anywhere in the tool result, in any
    // form. Check the private key with and without its 0x prefix, and the mnemonic.
    const full = JSON.stringify(response);
    assert(!full.includes(wallet.privateKey), "private key leaked into the tool result");
    assert(
      !full.includes(wallet.privateKey.replace(/^0x/, "")),
      "raw key hex leaked into the tool result",
    );
    assert(!full.includes(wallet.mnemonic), "mnemonic leaked into the tool result");
    const threeWords = wallet.mnemonic.split(/\s+/).slice(0, 3).join(" ");
    assert(!full.includes(threeWords), "mnemonic fragment leaked into the tool result");
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) Deno.env.delete(k);
      else Deno.env.set(k, v);
    }
    await rpc.shutdown();
    await Deno.remove(tmpHome, { recursive: true }).catch(() => {});
  }
});

// ---- 3. the child runner discards child stderr -----------------------------

Deno.test("spawnCaptureStdout drops child stderr entirely", async () => {
  // A child that writes a secret to stderr and clean JSON to stdout, exactly the
  // shape of `wallet new` revealing its one-time mnemonic on stderr.
  const run = await spawnCaptureStdout(Deno.execPath(), [
    "eval",
    "console.error('SUPERSECRET_MNEMONIC_abandon_ability_able'); console.log(JSON.stringify({ok:true,note:'clean'}));",
  ]);

  assert(run.json !== null, "expected a JSON object on stdout");
  assertEquals(run.json.ok, true);
  assertEquals(run.json.note, "clean");

  // The return type has no stderr field, and the secret written to stderr appears
  // nowhere in the captured result.
  assert(!("stderr" in run), "runner must not expose child stderr");
  const serialized = JSON.stringify(run);
  assert(!serialized.includes("SUPERSECRET"), "child stderr leaked through the runner");
});

// ---- 4. an unknown tool is a structured, secret-free error -----------------

Deno.test("unknown tool returns a structured error", async () => {
  const result = await executeTool("facet_not_a_tool", {});
  assertEquals(result.isError, true);
  const payload = JSON.parse(result.content[0].text) as { ok: boolean; error: string };
  assertEquals(payload.ok, false);
  assertStringIncludes(payload.error, "unknown tool");
});

// ---- 5. the tool table is internally consistent ----------------------------

Deno.test("tool table is internally consistent", () => {
  assertEquals(TOOLS.length, EXPECTED_TOOLS.length);
  for (const t of TOOLS) {
    assert(EXPECTED_TOOLS.includes(t.name), `unexpected tool ${t.name}`);
    assert(t.description.length > 0, `tool ${t.name} has no description`);
    // No em or en dash slipped into a description.
    const hasDash = [...t.description].some((c) => DASHES.includes(c));
    assert(!hasDash, `tool ${t.name} description has a dash`);
  }
});

// ---- 6. the withdraw wiring maps to the CLI subcommand ---------------------

Deno.test("facet_withdraw builds the withdraw subcommand argv", () => {
  const tool = TOOLS.find((t) => t.name === "facet_withdraw");
  assert(tool !== undefined, "facet_withdraw is not registered");
  const argv = tool.build!({
    terminal: "https://pecanandpetal.facet.llc",
    exchange_id: "42",
    wallet: "default",
    amount: "1250000",
    dry_run: true,
  });
  assertEquals(argv, [
    "withdraw",
    "--terminal",
    "https://pecanandpetal.facet.llc",
    "--exchange-id",
    "42",
    "--wallet",
    "default",
    "--amount",
    "1250000",
    "--dry-run",
  ]);
});

Deno.test("facet_withdraw omits optional flags and requires terminal + exchange_id", () => {
  const tool = TOOLS.find((t) => t.name === "facet_withdraw");
  assert(tool !== undefined, "facet_withdraw is not registered");
  // Minimal call: no wallet, no amount, no dry_run.
  assertEquals(tool.build!({ terminal: "https://x.facet.llc", exchange_id: "7" }), [
    "withdraw",
    "--terminal",
    "https://x.facet.llc",
    "--exchange-id",
    "7",
  ]);
  // exchange_id is required.
  let threw = false;
  try {
    tool.build!({ terminal: "https://x.facet.llc" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_withdraw must require exchange_id");
});

// ---- 6b. the MPP charge wiring maps to the CLI subcommand ------------------

Deno.test("facet_mpp_charge builds the mpp-charge subcommand argv (full settle)", () => {
  const tool = TOOLS.find((t) => t.name === "facet_mpp_charge");
  assert(tool !== undefined, "facet_mpp_charge is not registered");
  const argv = tool.build!({
    terminal: "https://pecanandpetal.facet.llc",
    reservation_id: "chk_abc123",
    wallet: "default",
    settle: true,
    confirm: "2524000",
    confirm_pay_to: "0x0be0574bd5fbd20e6187e6f3b6a889791699ccc3",
    max_usdc: 25,
  });
  assertEquals(argv, [
    "mpp-charge",
    "--terminal",
    "https://pecanandpetal.facet.llc",
    "--reservation-id",
    "chk_abc123",
    "--wallet",
    "default",
    "--settle",
    "--confirm",
    "2524000",
    "--confirm-pay-to",
    "0x0be0574bd5fbd20e6187e6f3b6a889791699ccc3",
    "--max-usdc",
    "25",
  ]);
});

Deno.test("facet_mpp_charge omits optional flags and requires terminal + reservation_id", () => {
  const tool = TOOLS.find((t) => t.name === "facet_mpp_charge");
  assert(tool !== undefined, "facet_mpp_charge is not registered");
  // Minimal DRY call: no wallet, no settle, no confirm.
  assertEquals(tool.build!({ terminal: "https://x.facet.llc", reservation_id: "r1" }), [
    "mpp-charge",
    "--terminal",
    "https://x.facet.llc",
    "--reservation-id",
    "r1",
  ]);
  // reservation_id is required.
  let threw = false;
  try {
    tool.build!({ terminal: "https://x.facet.llc" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_mpp_charge must require reservation_id");
});

Deno.test("facet_lifecycle_receipt builds the argv for an exchange-handled reversal", () => {
  const tool = TOOLS.find((t) => t.name === "facet_lifecycle_receipt");
  assert(tool !== undefined, "facet_lifecycle_receipt is not registered");
  assertEquals(
    tool.build!({
      terminal: "https://pecanandpetal.facet.llc",
      kind: "cancel",
      exchange_id: "42",
      wallet: "default",
    }),
    [
      "lifecycle-receipt",
      "--terminal",
      "https://pecanandpetal.facet.llc",
      "--kind",
      "cancel",
      "--exchange-id",
      "42",
      "--wallet",
      "default",
    ],
  );
});

Deno.test("facet_lifecycle_receipt takes an order handle for a refund and requires kind", () => {
  const tool = TOOLS.find((t) => t.name === "facet_lifecycle_receipt");
  assert(tool !== undefined, "facet_lifecycle_receipt is not registered");
  assertEquals(
    tool.build!({ terminal: "https://x.facet.llc", kind: "refund", order_id: "ord-9" }),
    [
      "lifecycle-receipt",
      "--terminal",
      "https://x.facet.llc",
      "--kind",
      "refund",
      "--order-id",
      "ord-9",
    ],
  );
  // kind is required.
  let threw = false;
  try {
    tool.build!({ terminal: "https://x.facet.llc" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_lifecycle_receipt must require kind");
});

Deno.test("facet_revise builds the cancel-and-rebuy planner argv with a kept-items array", () => {
  const tool = TOOLS.find((t) => t.name === "facet_revise");
  assert(tool !== undefined, "facet_revise is not registered");
  assertEquals(
    tool.build!({
      terminal: "https://pecanandpetal.facet.llc",
      exchange_id: "18",
      keep: [{ id: "HCF-BDAY", qty: 1 }],
      wallet: "default",
    }),
    [
      "revise",
      "--terminal",
      "https://pecanandpetal.facet.llc",
      "--exchange-id",
      "18",
      "--keep",
      '[{"id":"HCF-BDAY","qty":1}]',
      "--wallet",
      "default",
    ],
  );
  // exchange_id and keep are required.
  let threw = false;
  try {
    tool.build!({ terminal: "https://x.facet.llc" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_revise must require exchange_id and keep");
});

Deno.test("facet_cancel --withdraw chains the cash-out via one boolean flag", () => {
  const tool = TOOLS.find((t) => t.name === "facet_cancel");
  assert(tool !== undefined, "facet_cancel is not registered");
  // Plain cancel: no --withdraw appended.
  assertEquals(tool.build!({ terminal: "https://x.facet.llc", exchange_id: "7" }), [
    "cancel",
    "--terminal",
    "https://x.facet.llc",
    "--exchange-id",
    "7",
  ]);
  // cancel then withdraw, with an amount override.
  assertEquals(
    tool.build!({
      terminal: "https://x.facet.llc",
      exchange_id: "7",
      withdraw: true,
      amount: "500000",
    }),
    [
      "cancel",
      "--terminal",
      "https://x.facet.llc",
      "--exchange-id",
      "7",
      "--withdraw",
      "--amount",
      "500000",
    ],
  );
});

Deno.test("facet_refund builds the refund argv with reason and an optional partial selection", () => {
  const tool = TOOLS.find((t) => t.name === "facet_refund");
  assert(tool !== undefined, "facet_refund is not registered");
  // Whole-order refund: reason required, no items flag.
  assertEquals(
    tool.build!({ terminal: "https://x.facet.llc", order_id: "ord-1", reason: "changed my mind" }),
    [
      "refund",
      "--terminal",
      "https://x.facet.llc",
      "--order-id",
      "ord-1",
      "--reason",
      "changed my mind",
    ],
  );
  // Partial refund: the items array is serialized to a --items JSON flag.
  assertEquals(
    tool.build!({
      terminal: "https://x.facet.llc",
      order_id: "ord-1",
      reason: "arrived wilted",
      items: [{ id: "HCF-BDAY", qty: 1 }],
    }),
    [
      "refund",
      "--terminal",
      "https://x.facet.llc",
      "--order-id",
      "ord-1",
      "--reason",
      "arrived wilted",
      "--items",
      '[{"id":"HCF-BDAY","qty":1}]',
    ],
  );
  // reason is required.
  let threw = false;
  try {
    tool.build!({ terminal: "https://x.facet.llc", order_id: "ord-1" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_refund must require reason");
});

Deno.test("facet_fund builds the fund subcommand argv", () => {
  const tool = TOOLS.find((t) => t.name === "facet_fund");
  assert(tool !== undefined, "facet_fund is not registered");
  // One-shot balance check: no await, no minimum.
  assertEquals(tool.build!({}), ["fund"]);
  // Labeled wallet, poll until a minimum balance is reached.
  assertEquals(
    tool.build!({ label: "business", min_usdc: 25, await_funding: true }),
    ["fund", "--label", "business", "--min-usdc", "25", "--await"],
  );
});

Deno.test("facet_email_pref builds show, opt-in, and opt-out argv", () => {
  const tool = TOOLS.find((t) => t.name === "facet_email_pref");
  assert(tool !== undefined, "facet_email_pref is not registered");
  // show prints the current preference.
  assertEquals(tool.build!({ action: "show" }), ["email-pref", "show"]);
  // opt in: the address is a positional after set, not a --flag.
  assertEquals(
    tool.build!({ action: "set", address: "throwaway@example.com" }),
    ["email-pref", "set", "throwaway@example.com"],
  );
  // opt out: --none, no address.
  assertEquals(tool.build!({ action: "set", none: true }), ["email-pref", "set", "--none"]);
  // set without an address or none is rejected.
  let threw = false;
  try {
    tool.build!({ action: "set" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_email_pref set must require an address or none");
  // action is required.
  let threwAction = false;
  try {
    tool.build!({});
  } catch {
    threwAction = true;
  }
  assert(threwAction, "facet_email_pref must require an action");
});

Deno.test("facet_resolve builds the resolve argv for both the auto and explicit offer", () => {
  const tool = TOOLS.find((t) => t.name === "facet_resolve");
  assert(tool !== undefined, "facet_resolve is not registered");
  // Auto-fetch: just the refund_id (the offer is read from the buyer's own ticket).
  assertEquals(
    tool.build!({ terminal: "https://x.facet.llc", refund_id: "refund-1" }),
    ["resolve", "--terminal", "https://x.facet.llc", "--refund-id", "refund-1"],
  );
  // Explicit offer: exchange_id + buyer_percent_bps (a number, coerced) + seller_sig.
  assertEquals(
    tool.build!({
      terminal: "https://x.facet.llc",
      exchange_id: "42",
      buyer_percent_bps: 1140,
      seller_sig: "0xSELLERsig",
      wallet: "default",
    }),
    [
      "resolve",
      "--terminal",
      "https://x.facet.llc",
      "--exchange-id",
      "42",
      "--buyer-percent-bps",
      "1140",
      "--seller-sig",
      "0xSELLERsig",
      "--wallet",
      "default",
    ],
  );
  // terminal is required.
  let threw = false;
  try {
    tool.build!({ refund_id: "refund-1" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_resolve must require terminal");
});

// ---- 7. the receipt wiring maps to the CLI subcommands ---------------------

Deno.test("facet_get_receipt builds the receipt subcommand argv", () => {
  const tool = TOOLS.find((t) => t.name === "facet_get_receipt");
  assert(tool !== undefined, "facet_get_receipt is not registered");
  // Full call with the offline check skipped.
  assertEquals(
    tool.build!({
      terminal: "https://pecanandpetal.facet.llc",
      order_id: "bcd5ffa9-3d57-4749-9d0a-4a84a2c60137",
      no_verify: true,
      wallet: "default",
    }),
    [
      "receipt",
      "--terminal",
      "https://pecanandpetal.facet.llc",
      "--order-id",
      "bcd5ffa9-3d57-4749-9d0a-4a84a2c60137",
      "--no-verify",
      "--wallet",
      "default",
    ],
  );
  // Minimal call: no wallet, verify on.
  assertEquals(tool.build!({ terminal: "https://x.facet.llc", order_id: "7" }), [
    "receipt",
    "--terminal",
    "https://x.facet.llc",
    "--order-id",
    "7",
  ]);
  // order_id is required.
  let threw = false;
  try {
    tool.build!({ terminal: "https://x.facet.llc" });
  } catch {
    threw = true;
  }
  assert(threw, "facet_get_receipt must require order_id");
});

Deno.test("facet_receipts builds the no-argument receipts subcommand", () => {
  const tool = TOOLS.find((t) => t.name === "facet_receipts");
  assert(tool !== undefined, "facet_receipts is not registered");
  assertEquals(tool.build!({}), ["receipts"]);
});

Deno.test("facet_version builds the no-argument version subcommand", () => {
  const tool = TOOLS.find((t) => t.name === "facet_version");
  assert(tool !== undefined, "facet_version is not registered");
  assertEquals(tool.build!({}), ["version"]);
});

// ---- 8. per-line Boson escrow (the in-process set tools) -------------------
// The pure validators are exercised directly; the runners are exercised only
// through their validation short-circuit, which returns BEFORE any wallet or
// network access, so these tests need no key, no keychain, and no mocked RPC and
// they never weaken the secret invariant.

Deno.test("normalizeExchangeIds accepts an array or a comma string and dedupes in order", () => {
  // A native array: deduped preserving first-seen order, empties dropped.
  assertEquals(normalizeExchangeIds(["e1", "e2", "e1", "  ", "e3"]), ["e1", "e2", "e3"]);
  // A comma-separated string: trimmed and deduped the same way.
  assertEquals(normalizeExchangeIds(" e1 , e2 ,e1, ,e3 "), ["e1", "e2", "e3"]);
  // Neither an array nor a string is an empty set.
  assertEquals(normalizeExchangeIds(undefined), []);
  assertEquals(normalizeExchangeIds(42), []);
  // A string of only separators and whitespace normalizes to empty.
  assertEquals(normalizeExchangeIds(" , , "), []);
});

Deno.test("perLineBodyKey maps each kind to its Terminal set-body key", () => {
  assertEquals(perLineBodyKey("redeem"), "redeem_line_items");
  assertEquals(perLineBodyKey("cancel"), "cancel_line_items");
  assertEquals(perLineBodyKey("dispute"), "dispute_line_items");
});

Deno.test("planPerLineEscrowAction rejects passing both exchange_id and exchange_ids", () => {
  const plan = planPerLineEscrowAction("redeem", { exchange_id: "e1", exchange_ids: ["e2"] });
  assertEquals(plan.ok, false);
  if (!plan.ok) assertStringIncludes(plan.error, "mutually exclusive");
});

Deno.test("planPerLineEscrowAction rejects an empty exchange_ids set", () => {
  // Non-empty input that normalizes to empty, and the already-empty array.
  const a = planPerLineEscrowAction("redeem", { exchange_ids: ["  ", ""] });
  assertEquals(a.ok, false);
  if (!a.ok) assertStringIncludes(a.error, "empty");
  const b = planPerLineEscrowAction("dispute", { exchange_ids: [] });
  assertEquals(b.ok, false);
});

Deno.test("planPerLineEscrowAction rejects a per-line cancel that also asks to withdraw", () => {
  const plan = planPerLineEscrowAction("cancel", { exchange_ids: ["e1", "e2"], withdraw: true });
  assertEquals(plan.ok, false);
  if (!plan.ok) assertStringIncludes(plan.error, "withdraw is single-line only");
});

Deno.test("planPerLineEscrowAction validates the dispute action and defaults it to raise", () => {
  const bad = planPerLineEscrowAction("dispute", { exchange_ids: ["e1"], action: "bogus" });
  assertEquals(bad.ok, false);
  const def = planPerLineEscrowAction("dispute", { exchange_ids: ["e1"] });
  assertEquals(def.ok, true);
  if (def.ok) {
    assertEquals(def.action, "raise");
    assertEquals(def.exchangeIds, ["e1"]);
  }
  const esc = planPerLineEscrowAction("dispute", {
    exchange_ids: ["e1", "e2"],
    action: "escalate",
  });
  assertEquals(esc.ok, true);
  if (esc.ok) assertEquals(esc.action, "escalate");
});

Deno.test("the per-line action tools expose run and dispatch on exchange_ids", async () => {
  for (const name of ["facet_redeem", "facet_cancel", "facet_dispute"]) {
    const tool = TOOLS.find((t) => t.name === name);
    assert(tool !== undefined, `${name} is not registered`);
    assert(tool.run !== undefined, `${name} must expose an in-process run`);
    // No exchange_ids: run returns null so executeTool falls through to the spawn
    // (single-exchange) path. This must NOT touch the wallet or the network.
    const passthrough = await tool.run!({ terminal: "https://x.facet.llc" });
    assertEquals(passthrough, null, `${name} must fall through to the CLI without a set`);
    // A per-line set that fails validation (here: both single and set given) is
    // answered in-process as a structured error, again before any wallet or network.
    const both = await tool.run!({
      terminal: "https://x.facet.llc",
      exchange_id: "e1",
      exchange_ids: ["e2"],
    });
    assert(both !== null, `${name} must answer a per-line set in-process`);
    assertEquals(both.isError, true);
    const payload = JSON.parse(both.content[0].text) as { ok: boolean; error: string };
    assertEquals(payload.ok, false);
    assertStringIncludes(payload.error, "mutually exclusive");
    // The single-exchange CLI path is still wired for these tools.
    assert(tool.build !== undefined, `${name} must keep its single-exchange build`);
  }
});

Deno.test("facet_lines is a run-only reader with no spawn wiring", () => {
  const tool = TOOLS.find((t) => t.name === "facet_lines");
  assert(tool !== undefined, "facet_lines is not registered");
  assert(tool.run !== undefined, "facet_lines must expose an in-process run");
  // Run-only: there is no CLI subcommand behind it.
  assertEquals(tool.script, undefined);
  assertEquals(tool.build, undefined);
  assertEquals(tool.perms, undefined);
});

Deno.test("a per-line cancel with withdraw is refused in-process", async () => {
  const tool = TOOLS.find((t) => t.name === "facet_cancel");
  assert(tool !== undefined, "facet_cancel is not registered");
  const r = await tool.run!({
    terminal: "https://x.facet.llc",
    exchange_ids: ["e1", "e2"],
    withdraw: true,
  });
  assert(r !== null, "a per-line set must be handled in-process");
  assertEquals(r.isError, true);
  const payload = JSON.parse(r.content[0].text) as { ok: boolean; error: string };
  assertEquals(payload.ok, false);
  assertStringIncludes(payload.error, "withdraw is single-line only");
});
