#!/usr/bin/env -S deno run --allow-env --allow-read --allow-run
// mcp-server.ts
// A Model Context Protocol (MCP) server, stdio transport, that exposes the Facet
// buyer shopping workflow as MCP tools so an AUTONOMOUS agent can discover,
// identify, browse, and check out on Facet-enabled stores over MCP. Facet is
// designed to be walked by agents, not humans, so this is the agent-facing tool
// surface, not a human CLI.
//
// This is a THIN wrapper. Every tool spawns one of the existing skill scripts
// (facet-checkout.ts or browse-storefront.ts) as a child process and relays the
// ONE JSON object that child prints to stdout. No checkout, wallet, or KYA logic
// is reimplemented here: the child performs the offer validation, the local
// signing, and the settlement exactly as the CLI does. The cmd* handlers in
// facet-checkout.ts call Deno.exit and are not exported, so driving them as
// subprocesses is the only way to reuse the real flow without reimplementing it.
//
// THE SECRET INVARIANT (the reason this file is careful):
//   The wallet private key and the recovery mnemonic are read by the CHILD from
//   its environment and used to sign locally. The child prints only non-secret
//   JSON to stdout; the single place a secret is ever revealed is the one-time
//   mnemonic that `wallet new` writes to the child's STDERR. This server runs
//   every child with `stderr: "null"`, so that stream is discarded by the OS and
//   never enters this process, and it builds every tool result solely from the
//   child's STDOUT. A tool result therefore carries an address or a status,
//   never a secret. An MCP result is logged and persisted by the calling agent,
//   so stderr is held to the same bar the secret-egress rule holds stdout to: it
//   never reaches a tool response. The server itself never reads a wallet key or
//   mnemonic into a variable; the child inherits the environment directly.

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
  script: "facet-checkout.ts" | "browse-storefront.ts";
  perms: () => string[];
  build: (args: Args) => string[];
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
      "exchange_id is the settlement_id the buy receipt returned.",
    inputSchema: obj({ terminal: S, exchange_id: S, wallet: S }, [
      "terminal",
      "exchange_id",
    ]),
    script: "facet-checkout.ts",
    perms: facetPerms,
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
      "withdrawn atomic amount (default: the full available balance).",
    inputSchema: obj({ terminal: S, exchange_id: S, wallet: S, withdraw: B, amount: S }, [
      "terminal",
      "exchange_id",
    ]),
    script: "facet-checkout.ts",
    perms: facetPerms,
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
      "it carries the seller's counter-signature.",
    inputSchema: obj({
      terminal: S,
      exchange_id: S,
      action: { type: "string", enum: ["raise", "retract", "escalate"] },
      wallet: S,
    }, ["terminal", "exchange_id"]),
    script: "facet-checkout.ts",
    perms: facetPerms,
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
