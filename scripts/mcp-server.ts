#!/usr/bin/env -S deno run --allow-env --allow-read --allow-run --allow-net
// mcp-server.ts
// A Model Context Protocol (MCP) server, stdio transport, that exposes the Facet
// buyer shopping workflow as MCP tools so an AUTONOMOUS agent can discover,
// identify, browse, and check out on Facet-enabled stores over MCP. Facet is
// designed to be walked by agents, not humans, so this is the agent-facing tool
// surface, not a human CLI.
//
// This is a THIN wrapper, with ONE deliberate exception (stated below). Every
// SPAWN tool runs one of the existing skill scripts (facet-checkout.ts or
// browse-storefront.ts) as a child process and relays the ONE JSON object that
// child prints to stdout. No checkout, wallet, or KYA logic is reimplemented for
// those tools: the child performs the offer validation, the local signing, and
// the settlement exactly as the CLI does. The cmd* handlers in facet-checkout.ts
// call Deno.exit and are not exported, so driving them as subprocesses is the way
// to reuse the real flow without reimplementing it.
//
// THE SECRET INVARIANT (the reason this file is careful):
//   For a SPAWN tool, the wallet private key and the recovery mnemonic are read by
//   the CHILD from its environment and used to sign locally. The child prints only
//   non-secret JSON to stdout; the single place a secret is ever revealed is the
//   one-time mnemonic that `wallet new` writes to the child's STDERR. This server
//   runs every child with `stderr: "null"`, so that stream is discarded by the OS
//   and never enters this process, and it builds every tool result solely from the
//   child's STDOUT. A tool result therefore carries an address or a status, never a
//   secret. An MCP result is logged and persisted by the calling agent, so stderr
//   is held to the same bar the secret-egress rule holds stdout to: it never
//   reaches a tool response. For a spawn tool the server itself never reads a
//   wallet key or mnemonic into a variable; the child inherits the environment
//   directly.
//
// THE EXCEPTION (per-line Boson escrow, IN-PROCESS):
//   The per-line escrow tools (redeem / cancel / dispute over a SELECTION of
//   exchange_ids, and the facet_lines reader) do NOT spawn. They run in-process and
//   import the audited signing helpers from facet-checkout.ts (resolveWallet,
//   signBosonAction, walletBoundKya, kyaHeaders, terminalBase, DISPUTE_ACTION_ID),
//   and for those tools ONLY this server DOES read the wallet key into memory to
//   sign locally. That is a deliberate departure from the spawn-to-sign isolation
//   above, and it is necessary: a per-line action posts ONE request whose body is a
//   SET of line items, each carrying its own locally signed payload, and the
//   single-exchange CLI cannot assemble or post that set. The key is still held to
//   the same bar: it signs locally, each signed payload is posted to the Terminal,
//   and NEITHER the key NOR any raw signed payload is ever placed in a tool result.
//   A per-line tool result is only the Terminal's own JSON, or a structured,
//   secret-free error. Every OTHER tool still spawns the CLI unchanged.

import {
  DISPUTE_ACTION_ID,
  kyaHeaders,
  resolveWallet,
  signBosonAction,
  terminalBase,
  walletBoundKya,
} from "./facet-checkout.ts";

// ---- paths and permission profiles -----------------------------------------

const SCRIPT_DIR = import.meta.dirname ?? ".";

function scriptPath(name: string): string {
  return `${SCRIPT_DIR}/${name}`;
}

function homeDir(): string {
  return Deno.env.get("HOME") ?? Deno.env.get("USERPROFILE") ?? ".";
}

// facet-checkout.ts reads env at module load and, for any command that resolves a
// wallet minted by `wallet new`, touches the keychain (via `security`, needing
// --allow-run) and the encrypted keystore plus wallet index under ~/.facet. This
// is the documented maximal grant for the checkout script; each child still runs
// in Deno's sandbox with writes scoped to two directories.
function facetPerms(): string[] {
  const home = homeDir();
  return [
    "--allow-env",
    "--allow-read",
    `--allow-write=${home}/.cache,${home}/.facet`,
    "--allow-run",
    "--allow-net",
  ];
}

// browse-storefront.ts reads a public storefront over the network and touches no
// env, no files, and no secrets, so it gets network access only.
function browsePerms(): string[] {
  return ["--allow-net"];
}

// ---- argv builders ---------------------------------------------------------

type Args = Record<string, unknown>;

function requireArg(args: Args, name: string): string {
  const v = args[name];
  if (v === undefined || v === null || v === "") {
    throw new Error(`missing required argument: ${name}`);
  }
  return typeof v === "string" ? v : String(v);
}

function pushStr(argv: string[], flag: string, v: unknown): void {
  if (v === undefined || v === null || v === "") return;
  argv.push(`--${flag}`, typeof v === "string" ? v : String(v));
}

function pushBool(argv: string[], flag: string, v: unknown): void {
  if (v === true || v === "true") argv.push(`--${flag}`);
}

// items and ship are JSON. Accept either a pre-serialized string or a structured
// value and serialize it, so an agent can pass native arrays and objects.
function pushJson(argv: string[], flag: string, v: unknown): void {
  if (v === undefined || v === null) return;
  argv.push(`--${flag}`, typeof v === "string" ? v : JSON.stringify(v));
}

// ---- the tool table --------------------------------------------------------

interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  // A SPAWN tool defines script/perms/build: executeTool builds the child argv,
  // runs the child, and relays its stdout JSON. These are optional so a run-only
  // tool (the in-process per-line escrow tools) can omit them entirely.
  script?: "facet-checkout.ts" | "browse-storefront.ts";
  perms?: () => string[];
  build?: (args: Args) => string[];
  // An IN-PROCESS tool defines run. executeTool calls it BEFORE building/spawning:
  // a non-null result is returned directly; a null result falls through to the
  // spawn path, so one tool can serve a per-line SET in-process yet still spawn the
  // single-item CLI when no set was given.
  run?: (args: Args) => Promise<McpToolResult | null>;
}

function obj(
  properties: Record<string, unknown>,
  required: string[] = [],
): Record<string, unknown> {
  return {
    type: "object",
    properties,
    ...(required.length > 0 ? { required } : {}),
    additionalProperties: false,
  };
}

const S = { type: "string" } as const;
const B = { type: "boolean" } as const;
const N = { type: "number" } as const;

// ---- per-line Boson escrow (in-process) ------------------------------------
// The per-line escrow tools redeem / cancel / dispute a SELECTION of a committed
// multi-line order's exchanges in ONE request: the Terminal accepts a set body
// ({redeem,cancel,dispute}_line_items), each item carrying its own locally signed
// payload. Assembling and posting that set is why these tools run in-process (see
// THE EXCEPTION at the top of this file) rather than spawning the single-exchange
// CLI. The validators below are pure (no wallet, no network, no secrets) so they
// are unit-tested directly; the two runners hold the key with the same care the
// spawn path does and return only the Terminal's JSON or a structured error.

type PerLineKind = "redeem" | "cancel" | "dispute";

// Accept a string[] OR a comma-separated string; trim, drop empties, and dedupe
// preserving first-seen order. Pure.
export function normalizeExchangeIds(raw: unknown): string[] {
  let parts: string[];
  if (Array.isArray(raw)) {
    parts = raw.map((x) => (typeof x === "string" ? x : String(x)));
  } else if (typeof raw === "string") {
    parts = raw.split(",");
  } else {
    parts = [];
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of parts) {
    const id = p.trim();
    if (id === "" || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

// The Terminal set-body key for each per-line route. Pure.
export function perLineBodyKey(kind: PerLineKind): string {
  return kind === "redeem"
    ? "redeem_line_items"
    : kind === "cancel"
    ? "cancel_line_items"
    : "dispute_line_items";
}

// Validate the per-line arguments with no side effects: reject a single/set
// collision (exchange_id together with exchange_ids), an empty set, a per-line
// cancel that also asks to withdraw (withdraw is single-line only), and an invalid
// dispute action; otherwise return the deduped exchange ids and, for dispute, the
// validated action (default raise). Pure, so it is unit-tested directly.
export function planPerLineEscrowAction(
  kind: PerLineKind,
  args: Args,
): { ok: true; exchangeIds: string[]; action: string } | { ok: false; error: string } {
  const hasSingle = typeof args.exchange_id === "string"
    ? args.exchange_id !== ""
    : args.exchange_id !== undefined && args.exchange_id !== null;
  if (hasSingle) {
    return {
      ok: false,
      error:
        "exchange_id and exchange_ids are mutually exclusive: pass exchange_ids for a per-line set, or exchange_id for a single line.",
    };
  }
  const exchangeIds = normalizeExchangeIds(args.exchange_ids);
  if (exchangeIds.length === 0) {
    return { ok: false, error: "exchange_ids is empty: pass at least one exchange id." };
  }
  if (kind === "cancel" && (args.withdraw === true || args.withdraw === "true")) {
    return {
      ok: false,
      error:
        "per-line cancel does not support withdraw: withdraw is single-line only. Cancel the lines, then cash each out with facet_withdraw, or use exchange_id with withdraw for a single line.",
    };
  }
  let action = "";
  if (kind === "dispute") {
    action = typeof args.action === "string" ? args.action : "raise";
    if (action !== "raise" && action !== "retract" && action !== "escalate") {
      return {
        ok: false,
        error: `invalid dispute action "${action}": one of raise, retract, escalate.`,
      };
    }
  }
  return { ok: true, exchangeIds, action };
}

// Parse a single Terminal response body into a JSON object, or null when the body
// is not a JSON object (an HTML 502, a scalar, an array).
function parseObjectOrNull(text: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(text);
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // not JSON
  }
  return null;
}

// Turn a Terminal response (already read to text) into a secret-free tool result,
// mirroring the CLI lifecycle shapes: a dual-auth co-signature refusal on a 401/403
// whose body mentions a signature, a non-JSON body, or the Terminal's own JSON
// relayed with its ok flag. `label` names the action for the no-JSON message.
function terminalResponseResult(
  status: number,
  ok: boolean,
  text: string,
  label: string,
): McpToolResult {
  if ((status === 401 || status === 403) && /signature/i.test(text)) {
    return textResult(
      {
        ok: false,
        error:
          "this store requires a platform co-signature for this action; a buyer-only client cannot supply it.",
        reason: "platform_cosignature_required",
        http_status: status,
      },
      true,
    );
  }
  const json = parseObjectOrNull(text);
  if (json === null) {
    return textResult(
      { ok: false, error: `${label} returned no JSON object (HTTP ${status}).`, http_status: status },
      true,
    );
  }
  return textResult(json, !ok || json.ok === false);
}

// redeem / cancel / dispute a SELECTION of a committed order's lines in one
// request. Signs each line's payload locally with the buyer wallet key (read
// in-process, per THE EXCEPTION), assembles the set body, posts it on the buyer
// KYA, and returns ONLY the Terminal's JSON or a structured, secret-free error. The
// key and the raw signed payloads never enter the result.
async function runPerLineEscrowAction(kind: PerLineKind, args: Args): Promise<McpToolResult> {
  try {
    const plan = planPerLineEscrowAction(kind, args);
    if (!plan.ok) return textResult({ ok: false, error: plan.error }, true);

    const base = terminalBase(requireArg(args, "terminal"));
    const wallet = resolveWallet(typeof args.wallet === "string" ? args.wallet : undefined);
    const kya = await walletBoundKya(wallet);

    const actionId = kind === "redeem"
      ? "boson-redeem"
      : kind === "cancel"
      ? "boson-cancelVoucher"
      : DISPUTE_ACTION_ID[plan.action];

    const items: Array<Record<string, unknown>> = [];
    for (const exchangeId of plan.exchangeIds) {
      const signed_payload = await signBosonAction(wallet.key, actionId, exchangeId);
      items.push(
        kind === "dispute"
          ? { exchange_id: exchangeId, action: plan.action, signed_payload }
          : { exchange_id: exchangeId, signed_payload },
      );
    }

    const response = await fetch(`${base}/ucp/v1/checkout-sessions/${kind}`, {
      method: "POST",
      headers: kyaHeaders(kya),
      body: JSON.stringify({ [perLineBodyKey(kind)]: items }),
    });
    const text = await response.text();
    return terminalResponseResult(response.status, response.ok, text, `the ${kind} set request`);
  } catch (e) {
    return textResult({ ok: false, error: e instanceof Error ? e.message : String(e) }, true);
  }
}

// Read a committed per-line order's current escrow_lines (each line's own
// exchange_id, amount, currency, and state) so the agent can choose which lines to
// redeem / cancel / dispute. Owner-scoped at the Terminal on the buyer KYA. Returns
// only the session JSON or a structured, secret-free error.
async function runLinesRead(args: Args): Promise<McpToolResult> {
  try {
    const base = terminalBase(requireArg(args, "terminal"));
    const orderId = requireArg(args, "order_id");
    const wallet = resolveWallet(typeof args.wallet === "string" ? args.wallet : undefined);
    const kya = await walletBoundKya(wallet);
    const response = await fetch(`${base}/ucp/v1/checkout-sessions/${orderId}`, {
      headers: kyaHeaders(kya),
    });
    const text = await response.text();
    return terminalResponseResult(response.status, response.ok, text, "the lines read");
  } catch (e) {
    return textResult({ ok: false, error: e instanceof Error ? e.message : String(e) }, true);
  }
}

export const TOOLS: ToolDef[] = [
  {
    name: "facet_wallet_list",
    description: "List the buyer wallets this environment can shop from: label, public address, " +
      "USDC balance on the settlement network, and whether an identity is present. " +
      "Returns public data only; no private key or mnemonic is ever returned. Use this " +
      "first to choose which wallet pays.",
    inputSchema: obj({}),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: () => ["wallets"],
  },
  {
    name: "facet_wallet_new",
    description: "Mint a fresh self-custodied buyer wallet and store its key in the OS keychain " +
      "(or, if unavailable, an encrypted keystore). Returns the public address and " +
      "storage location only. The private key is never returned and the one-time " +
      "recovery phrase is written to the child process stderr, which this server " +
      "discards; it is intentionally not surfaced through MCP, because a tool result " +
      "is logged by the caller. To capture the recovery phrase a human must mint in a " +
      "terminal where that stderr is visible only to them.",
    inputSchema: obj({
      label: S,
      keystore: B,
      force: B,
    }),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["wallet", "new"];
      pushStr(v, "label", a.label);
      pushBool(v, "keystore", a.keystore);
      pushBool(v, "force", a.force);
      return v;
    },
  },
  {
    name: "facet_fund",
    description: "Show a buyer wallet's address and current USDC balance on the settlement " +
      "network so the user can send funds to it. Loads no key and moves no money. Set " +
      "await_funding true to poll until the balance is positive (or reaches min_usdc) and " +
      "report funded; omit it for a one-shot balance check. label selects the wallet by its " +
      "registry label (default the default wallet). Returns the address and balance only; " +
      "never a key.",
    inputSchema: obj({ label: S, min_usdc: N, await_funding: B }),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["fund"];
      pushStr(v, "label", a.label);
      pushStr(v, "min-usdc", a.min_usdc);
      pushBool(v, "await", a.await_funding);
      return v;
    },
  },
  {
    name: "facet_provision",
    description: "Self-issue a wallet-bound Facet KYA identity for the chosen wallet from the " +
      "public issuer, with no service key. The minted token is cached for reuse by " +
      "search and buy and is never printed or returned. Use when a store rejects the " +
      "current identity as untrusted, or to establish identity before an " +
      "identity-gated call.",
    inputSchema: obj({ wallet: S }),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["provision"];
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_discover",
    description: "Resolve one store's /.well-known/agents.txt to learn whether it runs a Facet " +
      "Terminal and where. Authoritative for a single host. Pass the bare host, for " +
      "example shop.example.com.",
    inputSchema: obj({ site: S }, ["site"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["discover"];
      pushStr(v, "site", requireArg(a, "site"));
      return v;
    },
  },
  {
    name: "facet_directory",
    description: "Search the Facet directory (identity-gated) for merchants that fit a query, " +
      "location, capability, or taxonomy, and see which have a live Terminal. Use to " +
      "find a store from an intent, and to resolve a canonical Terminal URL by " +
      "business name.",
    inputSchema: obj({
      query: S,
      near: S,
      radius_km: N,
      taxonomy: S,
      capabilities: S,
      min_reputation: N,
      claimed_only: B,
      limit: N,
      terminal: S,
    }),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["directory"];
      pushStr(v, "query", a.query);
      pushStr(v, "near", a.near);
      pushStr(v, "radius-km", a.radius_km);
      pushStr(v, "taxonomy", a.taxonomy);
      pushStr(v, "capabilities", a.capabilities);
      pushStr(v, "min-reputation", a.min_reputation);
      pushBool(v, "claimed-only", a.claimed_only);
      pushStr(v, "limit", a.limit);
      pushStr(v, "terminal", a.terminal);
      return v;
    },
  },
  {
    name: "facet_search",
    description: "Read a merchant's own agent-native transaction catalog from its Terminal " +
      "(identity-gated, given not scraped). Returns products with the SKU that is the " +
      "join key to buy. Prefer this over browse_storefront when a Terminal URL is " +
      "known.",
    inputSchema: obj({
      terminal: S,
      query: S,
      category: S,
      tags: S,
      limit: N,
      cursor: S,
    }, ["terminal"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["search"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "query", a.query);
      pushStr(v, "category", a.category);
      pushStr(v, "tags", a.tags);
      pushStr(v, "limit", a.limit);
      pushStr(v, "cursor", a.cursor);
      return v;
    },
  },
  {
    name: "facet_product",
    description: "Read one product's rail detail from a Terminal by its SKU id, including the " +
      "settlement rail the store advertises for it.",
    inputSchema: obj({ terminal: S, id: S }, ["terminal", "id"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["product"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "id", requireArg(a, "id"));
      return v;
    },
  },
  {
    name: "facet_buy",
    description: "Run the UCP checkout. DRY by default: it creates the checkout session, reads " +
      "the seller-signed offer, validates it against the buyer guardrails, signs the " +
      "payment authorization locally, and stops, returning the exact price and the " +
      "confirm values. Nothing moves. To settle real money, call again with settle " +
      "true and confirm set to the exact atomic price the dry run returned, only " +
      "after the user has approved that total. On the x402-direct rail the dry run also " +
      "returns confirm_pay_to (the recipient), which must be passed back on settle: the " +
      "x402 recipient is not escrow-pinned, so it is confirmed like the amount. items is " +
      "an array of { id, qty }; ship is the shipping address object. The wallet key never " +
      "leaves the child process.",
    inputSchema: obj({
      terminal: S,
      items: { type: ["array", "string"] },
      ship: { type: ["object", "string"] },
      wallet: S,
      settle: B,
      confirm: S,
      confirm_pay_to: S,
      max_usdc: N,
      gift_message: S,
      delivery_date: S,
      occasion: S,
    }, ["terminal", "items", "ship"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["buy"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      if (a.items === undefined || a.items === null) {
        throw new Error("missing required argument: items");
      }
      if (a.ship === undefined || a.ship === null) {
        throw new Error("missing required argument: ship");
      }
      pushJson(v, "items", a.items);
      pushJson(v, "ship", a.ship);
      pushStr(v, "wallet", a.wallet);
      pushBool(v, "settle", a.settle);
      pushStr(v, "confirm", a.confirm);
      pushStr(v, "confirm-pay-to", a.confirm_pay_to);
      pushStr(v, "max-usdc", a.max_usdc);
      pushStr(v, "gift-message", a.gift_message);
      pushStr(v, "delivery-date", a.delivery_date);
      pushStr(v, "occasion", a.occasion);
      return v;
    },
  },
  {
    name: "facet_mpp_charge",
    description: "Pay a held reservation through the Machine Payments Protocol (mpp.dev) charge " +
      "envelope, for an mpp.dev-native flow. MPP is not a separate rail: it is the same on-chain " +
      "settlement re-dressed in mpp.dev's challenge/credential/receipt shape. Reserve first (call " +
      "facet_buy in DRY mode and use its checkout_id, or POST /v1/reserve) and pass that as " +
      "reservation_id. DRY by default: it probes the charge endpoint, reads the server-derived " +
      "challenge (amount, recipient, currency, chain), validates it against the buyer guardrails, " +
      "and stops, returning confirm_atomic and confirm_pay_to. Nothing moves. To settle real USDC, " +
      "call again with settle true, confirm set to the exact atomic amount the dry run returned, and " +
      "confirm_pay_to set to the recipient it returned, only after the user approved that total. The " +
      "credential is signed locally and the wallet key never leaves the child process. MPP settles " +
      "x402-direct with no escrow, so it REFUSES on any merchant that offers Boson escrow (it reads the " +
      "reservation's rails first) and points you to facet_buy instead: MPP never bypasses escrow.",
    inputSchema: obj({
      terminal: S,
      reservation_id: S,
      wallet: S,
      settle: B,
      confirm: S,
      confirm_pay_to: S,
      max_usdc: N,
    }, ["terminal", "reservation_id"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["mpp-charge"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "reservation-id", requireArg(a, "reservation_id"));
      pushStr(v, "wallet", a.wallet);
      pushBool(v, "settle", a.settle);
      pushStr(v, "confirm", a.confirm);
      pushStr(v, "confirm-pay-to", a.confirm_pay_to);
      pushStr(v, "max-usdc", a.max_usdc);
      return v;
    },
  },
  {
    name: "facet_email_pref",
    description: "Record or read the buyer's throwaway shipping-confirmation email, asked once " +
      "and reused on every later order so the agent never asks twice. action show prints the " +
      "current preference. action set with address opts in and stores that address; action " +
      "set with none true opts out, so the agent stops asking. When opted in, buy attaches " +
      "the stored address to the order automatically. The address is buyer-provided and " +
      "non-secret; it is stored as plain JSON under the cache dir, never the keystore.",
    inputSchema: obj({
      action: { type: "string", enum: ["show", "set"] },
      address: S,
      none: B,
    }, ["action"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const action = requireArg(a, "action");
      const v = ["email-pref", action];
      if (action === "set") {
        if (a.none === true || a.none === "true") {
          v.push("--none");
        } else {
          v.push(requireArg(a, "address"));
        }
      }
      return v;
    },
  },
  {
    name: "facet_browse_storefront",
    description: "Last-resort reader for a merchant's PUBLIC, human-facing storefront when " +
      "neither the assistant's own browser nor a Terminal search is available. Reads " +
      "the public catalog (WooCommerce Store API, then JSON-LD) and returns a lean " +
      "product list with SKUs. Needs no identity, no wallet, and no secrets.",
    inputSchema: obj({ site: S, query: S, limit: N }, ["site"]),
    script: "browse-storefront.ts",
    perms: browsePerms,
    build: (a) => {
      const v: string[] = [];
      pushStr(v, "site", requireArg(a, "site"));
      pushStr(v, "query", a.query);
      pushStr(v, "limit", a.limit);
      return v;
    },
  },
  {
    name: "facet_redeem",
    description: "Redeem a settled Boson escrow order: confirm the goods arrived and release the " +
      "escrow to the seller. Signed locally and gasless with the buyer's own wallet. " +
      "exchange_id is the settlement_id the buy receipt returned. For a committed per-line " +
      "(multi-item) order, pass exchange_ids (a string array, or a comma-separated string) " +
      "instead to redeem a SELECTION of lines at once: each line is signed locally and posted " +
      "as one set, and the result summarizes it with a top-level status plus counts and a " +
      "per-line lines[] array. Pass exactly one of exchange_id or exchange_ids; read the lines " +
      "first with facet_lines.",
    inputSchema: obj({
      terminal: S,
      exchange_id: S,
      exchange_ids: { type: "array", items: { type: "string" } },
      wallet: S,
    }, ["terminal"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    run: (a) =>
      (Array.isArray(a.exchange_ids) && a.exchange_ids.length > 0) ||
        (typeof a.exchange_ids === "string" && a.exchange_ids !== "")
        ? runPerLineEscrowAction("redeem", a)
        : Promise.resolve(null),
    build: (a) => {
      const v = ["redeem"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "exchange-id", requireArg(a, "exchange_id"));
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_cancel",
    description: "Cancel a Boson escrow order before redemption: the full escrow returns to the " +
      "buyer's protocol available-funds. Signed locally and gasless with the buyer's " +
      "own wallet. exchange_id is the settlement_id the buy receipt returned. Set " +
      "withdraw true to also cash the returned escrow out to the buyer's own wallet in " +
      "the same call (cancel, then a gasless withdraw); amount optionally overrides the " +
      "withdrawn atomic amount (default: the full available balance). For a committed " +
      "per-line (multi-item) order, pass exchange_ids (a string array, or a comma-separated " +
      "string) instead to cancel a SELECTION of lines at once: each line is signed locally " +
      "and posted as one set, and the result summarizes it with a top-level status plus counts " +
      "and a per-line lines[] array. Pass exactly one of exchange_id or exchange_ids; withdraw " +
      "is single-line only, so it cannot be combined with exchange_ids.",
    inputSchema: obj({
      terminal: S,
      exchange_id: S,
      exchange_ids: { type: "array", items: { type: "string" } },
      wallet: S,
      withdraw: B,
      amount: S,
    }, ["terminal"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    run: (a) =>
      (Array.isArray(a.exchange_ids) && a.exchange_ids.length > 0) ||
        (typeof a.exchange_ids === "string" && a.exchange_ids !== "")
        ? runPerLineEscrowAction("cancel", a)
        : Promise.resolve(null),
    build: (a) => {
      const v = ["cancel"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "exchange-id", requireArg(a, "exchange_id"));
      pushStr(v, "wallet", a.wallet);
      pushBool(v, "withdraw", a.withdraw);
      pushStr(v, "amount", a.amount);
      return v;
    },
  },
  {
    name: "facet_withdraw",
    description: "Cash out a Boson escrow's returned available-funds to the buyer's OWN wallet, " +
      "gaslessly. After a cancel (or seller revoke) the escrowed USDC sits in the " +
      "buyer's Boson protocol available-funds; this signs the buyer's withdrawFunds " +
      "meta-tx locally and a gas-only relayer submits it (withdrawFunds is self-binding " +
      "on-chain, so the funds can only go to the buyer's own wallet). exchange_id is the " +
      "settlement_id the buy receipt returned. amount optionally overrides the atomic " +
      "amount (default: the full available balance). Set dry_run true to gather, sign, " +
      "and return the exact request body WITHOUT posting, for inspection before a real " +
      "cash-out. Returns status, tx, and amount; never a key.",
    inputSchema: obj({ terminal: S, exchange_id: S, wallet: S, amount: S, dry_run: B }, [
      "terminal",
      "exchange_id",
    ]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["withdraw"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "exchange-id", requireArg(a, "exchange_id"));
      pushStr(v, "wallet", a.wallet);
      pushStr(v, "amount", a.amount);
      pushBool(v, "dry-run", a.dry_run);
      return v;
    },
  },
  {
    name: "facet_dispute",
    description: "Raise, retract, or escalate a dispute on a Boson escrow order. Signed locally " +
      "and gasless with the buyer's own wallet. action is one of raise, retract, " +
      "escalate (default raise). To complete a partial-refund split, use facet_resolve: " +
      "it carries the seller's counter-signature. For a committed per-line (multi-item) order, " +
      "pass exchange_ids (a string array, or a comma-separated string) instead to apply the " +
      "same action to a SELECTION of lines at once: each line is signed locally and posted as " +
      "one set, and the result summarizes it with a top-level status plus counts and a per-line " +
      "lines[] array. Pass exactly one of exchange_id or exchange_ids; read the lines first with " +
      "facet_lines.",
    inputSchema: obj({
      terminal: S,
      exchange_id: S,
      exchange_ids: { type: "array", items: { type: "string" } },
      action: { type: "string", enum: ["raise", "retract", "escalate"] },
      wallet: S,
    }, ["terminal"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    run: (a) =>
      (Array.isArray(a.exchange_ids) && a.exchange_ids.length > 0) ||
        (typeof a.exchange_ids === "string" && a.exchange_ids !== "")
        ? runPerLineEscrowAction("dispute", a)
        : Promise.resolve(null),
    build: (a) => {
      const v = ["dispute"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "exchange-id", requireArg(a, "exchange_id"));
      pushStr(v, "action", a.action);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_lines",
    description: "Read a committed per-line (multi-item) Boson order's current escrow lines so the " +
      "agent can choose which lines to act on. Returns the order's escrow_lines: each line's own " +
      "line_index, exchange_id, amount, currency, and exchange_state (plus status), owner-scoped " +
      "to the caller's wallet-bound identity. Runs in-process on the buyer KYA and reads only; it " +
      "moves no money and returns no key. Use it before facet_redeem, facet_cancel, or " +
      "facet_dispute with exchange_ids to target specific lines. order_id is the order id the buy " +
      "receipt returned.",
    inputSchema: obj({ terminal: S, order_id: S, wallet: S }, ["terminal", "order_id"]),
    run: (a) => runLinesRead(a),
  },
  {
    name: "facet_refund",
    description: "Open a refund ticket for a settled order. REQUEST only: it opens the ticket and " +
      "moves no money; the merchant reviews the reason and approves, which dispatches the " +
      "send-back (x402 order) or offers a resolveDispute split (Boson order) the buyer completes " +
      "with facet_resolve. reason is required. Pass items (an array of { id, qty }) for a PARTIAL " +
      "refund of just those lines, with shipping retained; omit items to request the whole order. " +
      "On a store that gates the request behind a platform co-signature, it authorizes itself with " +
      "a single-use, order-bound wallet attestation signed locally, so a buyer-only agent can open " +
      "the ticket with no platform in the loop; a single-factor store ignores it. order_id is the " +
      "order id the buy receipt returned.",
    inputSchema: obj({
      terminal: S,
      order_id: S,
      reason: S,
      items: { type: ["array", "string"] },
      wallet: S,
    }, ["terminal", "order_id", "reason"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["refund"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "order-id", requireArg(a, "order_id"));
      pushStr(v, "reason", requireArg(a, "reason"));
      if (a.items !== undefined && a.items !== null) pushJson(v, "items", a.items);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_resolve",
    description: "Complete a Boson partial-refund split (a mutual resolveDispute) after the " +
      "merchant approves. Signs the buyer half locally and gaslessly with the buyer's own " +
      "wallet and submits it; the Terminal validates the split against the merchant's stored " +
      "offer before relaying, so the buyer cannot alter the percentage or the seller half. " +
      "Give refund_id to auto-read the approved offer from the buyer's own refund ticket, OR " +
      "pass the offer explicitly with exchange_id, buyer_percent_bps, and seller_sig. The " +
      "wallet key never leaves the child process.",
    inputSchema: obj({
      terminal: S,
      refund_id: S,
      exchange_id: S,
      buyer_percent_bps: N,
      seller_sig: S,
      wallet: S,
    }, ["terminal"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["resolve"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "refund-id", a.refund_id);
      pushStr(v, "exchange-id", a.exchange_id);
      pushStr(v, "buyer-percent-bps", a.buyer_percent_bps);
      pushStr(v, "seller-sig", a.seller_sig);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_reorder",
    description: "Buy a past order again. Reads the buyer's own order history (owner " +
      "scoped to the caller's identity), then for each past item reads the CURRENT " +
      "price and availability, and returns the reorder candidates plus a buy plan. " +
      "Pure orchestration: it settles nothing and buys nothing on its own. A SKU that " +
      "is gone or out of stock is marked unavailable and skipped, never fatal. The " +
      "actual purchase runs through facet_buy exactly like any other checkout: DRY " +
      "first, an explicit user confirmation, then settle. With order_id it reorders " +
      "that order; without it, the most recent order. No key or mnemonic is ever returned.",
    inputSchema: obj({ terminal: S, order_id: S, limit: N, wallet: S }, ["terminal"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["reorder"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "order-id", a.order_id);
      pushStr(v, "limit", a.limit);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_revise",
    description: "Plan a change to a multi-item order BEFORE it ships. Boson cannot partially " +
      "refund a committed escrow, so the non-custodial equivalent is cancel-and-rebuy: cancel the " +
      "whole order (the full escrow refunds, cashed back to the wallet) then re-buy only the kept " +
      "items. This returns the two-step plan (the exact cancel and buy commands) and moves NO " +
      "money on its own, like facet_reorder. exchange_id is the escrow to cancel; keep is an array " +
      "of { id, qty } for the items to keep and re-buy. Each leg leaves a signed receipt (the " +
      "cancel a facet-lifecycle+jws, the rebuy a settlement receipt). Run the two commands through " +
      "facet_cancel and facet_buy, confirming each. No key is ever returned.",
    inputSchema: obj({
      terminal: S,
      exchange_id: S,
      keep: { type: ["array", "string"] },
      wallet: S,
    }, ["terminal", "exchange_id", "keep"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["revise"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "exchange-id", requireArg(a, "exchange_id"));
      // keep is required, but pass it straight to pushJson so a native array is
      // JSON-serialized (requireArg coerces to a string first, which mangles it);
      // a missing keep still fails at the CLI via requireFlag.
      pushJson(v, "keep", a.keep);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_get_receipt",
    description: "Fetch and verify the Facet ledger's signed settlement receipt for a settled " +
      "order. The receipt is a compact Ed25519 JWS (RFC 7515) verified offline against the " +
      "merchant Terminal's published JWKS, with no call back to Facet. A settled buy already " +
      "returns this inline; use this to re-fetch or independently verify any past order. If the " +
      "original buyer identity has expired it re-authorizes by signing a challenge with the " +
      "paying wallet, so the wallet that paid can always retrieve its own receipts. Set " +
      "no_verify true to return the raw receipt without the offline signature check. order_id is " +
      "the order id the buy receipt returned. Every fetched receipt is also saved to the local " +
      "archive. Returns the receipt and its verified flag; never a key.",
    inputSchema: obj({ terminal: S, order_id: S, no_verify: B, wallet: S }, [
      "terminal",
      "order_id",
    ]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["receipt"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "order-id", requireArg(a, "order_id"));
      pushBool(v, "no-verify", a.no_verify);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_render_receipt",
    description: "Render a settled order's receipt into the OFFICIAL, self-contained, self-verifying " +
      "HTML page (the one canonical Facet receipt view). Every field is derived in the page from the " +
      "embedded signed JWS, the merchant's Ed25519 public key is embedded so the verify seal is a real " +
      "in-browser check, and the identity, payment, and verification provenance chain renders when it is " +
      "available (from the archive a settled buy wrote, or an explicit provenance_file). Writes the HTML " +
      "and returns its path; nothing on the receipt is secret, so the file is shareable. order_id is the " +
      "order id the buy receipt returned; merchant_name is an optional display name; out is an optional " +
      "output path (defaults under the receipts archive).",
    inputSchema: obj({
      terminal: S,
      order_id: S,
      wallet: S,
      merchant_name: S,
      merchant_location: S,
      order_url: S,
      provenance_file: S,
      out: S,
    }, ["terminal", "order_id"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["render-receipt"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "order-id", requireArg(a, "order_id"));
      pushStr(v, "wallet", a.wallet);
      pushStr(v, "merchant-name", a.merchant_name);
      pushStr(v, "merchant-location", a.merchant_location);
      pushStr(v, "order-url", a.order_url);
      pushStr(v, "provenance-file", a.provenance_file);
      pushStr(v, "out", a.out);
      return v;
    },
  },
  {
    name: "facet_lifecycle_receipt",
    description: "Fetch, verify, and archive the signed REVERSAL receipt for a cancel, withdraw, " +
      "dispute, or refund (the lifecycle analogue of facet_get_receipt). A compact Ed25519 JWS " +
      "(typ facet-lifecycle+jws) verified offline against the merchant Terminal's published JWKS. " +
      "The reversal tools (facet_cancel / facet_withdraw / facet_dispute) already archive it " +
      "inline; use this to re-fetch it, or to fetch one performed earlier in the same wallet-bound " +
      "identity. kind is one of cancel / withdraw / dispute / refund; pass exchange_id for cancel / " +
      "withdraw / dispute, or order_id for a refund. Owner-scoped at the Terminal: it resolves only " +
      "for the identity that performed the reversal (a 404 otherwise, never a leak). Returns the " +
      "receipt and its verified flag; never a key.",
    inputSchema: obj({ terminal: S, kind: S, exchange_id: S, order_id: S, wallet: S }, [
      "terminal",
      "kind",
    ]),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: (a) => {
      const v = ["lifecycle-receipt"];
      pushStr(v, "terminal", requireArg(a, "terminal"));
      pushStr(v, "kind", requireArg(a, "kind"));
      pushStr(v, "exchange-id", a.exchange_id);
      pushStr(v, "order-id", a.order_id);
      pushStr(v, "wallet", a.wallet);
      return v;
    },
  },
  {
    name: "facet_receipts",
    description: "List the local receipt archive: every settlement receipt this environment has " +
      "fetched, most recent first, each with its order id, rail, amount, and verified flag. " +
      "Reads only local files under the receipts folder (default the buyer's own home, override " +
      "with FACET_RECEIPTS_DIR); needs no wallet and no network. Use when the user asks about " +
      "their past purchases, rather than re-fetching each order. Returns public receipt metadata " +
      "only; never a key.",
    inputSchema: obj({}),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: () => ["receipts"],
  },
  {
    name: "facet_version",
    description: "Confirm the installed skill against the latest GA release. Reads the newest " +
      "published tag from the public GA repository's GitHub API (Facet-llc/shopping-skill) and " +
      "compares it to this build's version, returning `version`, `latest`, `up_to_date`, and a " +
      "human `message`, plus an `update_url` when a newer release exists. Read-only: no wallet, no " +
      "KYA, no secret; a GitHub outage reports `up_to_date: null` (unknown), never an error. Use " +
      "when the user asks whether the skill is up to date or on the latest version.",
    inputSchema: obj({}),
    script: "facet-checkout.ts",
    perms: facetPerms,
    build: () => ["version"],
  },
];

// ---- the child runner (the secret choke point) -----------------------------

export interface ToolRun {
  code: number;
  json: Record<string, unknown> | null;
  stdout: string;
}

// Parse the LAST JSON object printed on stdout. The scripts emit exactly one, but
// scanning from the end is robust to a stray leading line.
function lastJsonObject(text: string): Record<string, unknown> | null {
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i]);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // not JSON; keep scanning earlier lines
    }
  }
  return null;
}

// Run a child and capture ONLY its stdout. stderr is sent to "null" so a secret a
// child writes there (the one-time mnemonic on `wallet new`) is discarded by the
// OS and never enters this process. The return type has no stderr field by
// construction, so no caller can forward it into a tool result. The child inherits
// this process's environment (which is where the wallet key lives); this server
// never reads that key into a variable.
export async function spawnCaptureStdout(
  exe: string,
  args: string[],
): Promise<ToolRun> {
  const command = new Deno.Command(exe, {
    args,
    stdin: "null",
    stdout: "piped",
    stderr: "null",
  });
  const { code, stdout } = await command.output();
  const text = new TextDecoder().decode(stdout);
  return { code, json: lastJsonObject(text), stdout: text };
}

export interface McpToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError: boolean;
}

function textResult(payload: Record<string, unknown>, isError: boolean): McpToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload) }], isError };
}

// Execute a named tool: build the child argv, run it, and relay its stdout JSON.
// Every failure path returns a structured, secret-free result.
export async function executeTool(name: string, args: Args): Promise<McpToolResult> {
  const tool = TOOLS.find((t) => t.name === name);
  if (tool === undefined) {
    return textResult({ ok: false, error: `unknown tool: ${name}` }, true);
  }
  // In-process path first. A run-only tool (facet_lines) always answers here; a
  // dual-mode tool (redeem / cancel / dispute) answers here only for a per-line
  // SET and returns null for the single-exchange case, which falls through to the
  // spawn path below. The runners self-wrap every failure into a structured result.
  if (tool.run !== undefined) {
    const r = await tool.run(args ?? {});
    if (r !== null) return r;
  }
  // Spawn path. A run-only tool that returned null has no CLI fallback: that is a
  // bug, not a valid state, so report it structurally rather than dereferencing an
  // absent build/script/perms.
  if (tool.build === undefined || tool.script === undefined || tool.perms === undefined) {
    return textResult(
      { ok: false, error: `tool ${name} has no spawn path and its in-process run returned null.` },
      true,
    );
  }
  let sub: string[];
  try {
    sub = tool.build(args ?? {});
  } catch (e) {
    return textResult(
      { ok: false, error: e instanceof Error ? e.message : String(e) },
      true,
    );
  }
  const childArgs = ["run", ...tool.perms(), scriptPath(tool.script), ...sub];
  const run = await spawnCaptureStdout(Deno.execPath(), childArgs);
  if (run.json === null) {
    // No JSON on stdout. Report the exit code only; the child's stderr (which may
    // carry a secret) is never included.
    return textResult(
      {
        ok: false,
        error: `the ${name} tool produced no JSON object on stdout (child exit ${run.code}).`,
      },
      true,
    );
  }
  const isError = run.code !== 0 || run.json.ok === false;
  return { content: [{ type: "text", text: JSON.stringify(run.json) }], isError };
}

// ---- JSON-RPC / MCP dispatch -----------------------------------------------

const SERVER_INFO = { name: "facet-shopping", version: "0.1.0" };
const SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];

interface RpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

function rpcResult(id: string | number | null, result: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(
  id: string | number | null,
  code: number,
  message: string,
): Record<string, unknown> {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function pickProtocol(requested: unknown): string {
  if (typeof requested === "string" && SUPPORTED_PROTOCOLS.includes(requested)) {
    return requested;
  }
  return SUPPORTED_PROTOCOLS[0];
}

function publicTool(t: ToolDef): Record<string, unknown> {
  return { name: t.name, description: t.description, inputSchema: t.inputSchema };
}

// Handle one JSON-RPC message. Returns the response object, or null for a
// notification (no reply expected).
export async function handleMessage(msg: RpcMessage): Promise<Record<string, unknown> | null> {
  const id = msg.id ?? null;
  switch (msg.method) {
    case "initialize":
      return rpcResult(id, {
        protocolVersion: pickProtocol(msg.params?.protocolVersion),
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
    case "notifications/initialized":
    case "notifications/cancelled":
      return null;
    case "ping":
      return rpcResult(id, {});
    case "tools/list":
      return rpcResult(id, { tools: TOOLS.map(publicTool) });
    case "tools/call": {
      const params = msg.params ?? {};
      const name = typeof params.name === "string" ? params.name : "";
      const callArgs = (params.arguments ?? {}) as Args;
      const result = await executeTool(name, callArgs);
      return rpcResult(id, result);
    }
    default:
      // A notification we do not handle has no id and expects no reply.
      if (msg.id === undefined) return null;
      return rpcError(id, -32601, `method not found: ${msg.method ?? ""}`);
  }
}

// ---- stdio transport -------------------------------------------------------

async function writeMessage(obj: Record<string, unknown>): Promise<void> {
  const line = JSON.stringify(obj) + "\n";
  await Deno.stdout.write(new TextEncoder().encode(line));
}

// Read newline-delimited JSON-RPC messages from stdin and answer on stdout. Only
// JSON-RPC frames are ever written to stdout; all diagnostics go to stderr.
async function serveStdio(): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";
  for await (const chunk of Deno.stdin.readable) {
    buffer += decoder.decode(chunk, { stream: true });
    let nl = buffer.indexOf("\n");
    while (nl >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      nl = buffer.indexOf("\n");
      if (line.length === 0) continue;
      let msg: RpcMessage;
      try {
        msg = JSON.parse(line) as RpcMessage;
      } catch {
        await writeMessage(rpcError(null, -32700, "parse error"));
        continue;
      }
      try {
        const response = await handleMessage(msg);
        if (response !== null) await writeMessage(response);
      } catch (e) {
        const id = msg.id ?? null;
        await writeMessage(
          rpcError(id, -32603, `internal error: ${e instanceof Error ? e.message : String(e)}`),
        );
      }
    }
  }
}

if (import.meta.main) {
  await serveStdio();
}
