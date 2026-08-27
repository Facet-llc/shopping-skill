// Official Facet receipt renderer.
//
// Fills references/receipt-template.html (the ONE canonical receipt rendering)
// with a receipt's data and returns a self-contained, self-verifying HTML page.
//
// The template is rendered SERVER-SIDE here: every displayed field (amount, split,
// settlement, signed-by, the identity/payment provenance, the ledger link) is
// filled into the markup so the receipt shows its content even without JavaScript,
// which is what a static "signed ledger record" should do. The embedded page
// script is left to do only what needs the browser: the live in-browser Ed25519
// check against the embedded merchant key, the copy button, and the light/dark
// toggle.
//
// These functions are PURE (no I/O, no secrets) so they are unit-tested offline.
// The fetch-and-write orchestration lives in facet-checkout.ts's `render-receipt`
// subcommand, which holds the receipt-fetch helpers.

/** One recorded signed lifecycle (reversal) receipt: a compact Ed25519 JWS
 *  (typ facet-lifecycle+jws) for a cancel / withdraw / dispute / refund, verifiable
 *  offline against the merchant JWKS. Embedded in the receipt's Amendments section so
 *  the reversal signatures travel with it, exactly as the settlement JWS does. */
export type ReversalSignature = {
  readonly kind: string;
  readonly jws: string;
  readonly kid?: string;
  readonly tx_hash?: string;
  readonly verified?: boolean | null;
};

export interface ReceiptRenderInput {
  /** The compact receipt JWS (header.payload.signature). */
  readonly jws: string;
  /** The Ed25519 public key (JWK `x`, base64url) for the receipt's `kid`, or
   *  null when the JWKS could not be fetched; the page then shows the offline
   *  verdict instead of an in-page check. */
  readonly pubkeyX: string | null;
  /** The offline verification verdict computed at render time (verifyReceipt).
   *  Sets the seal's STATIC resting state so a no-JS viewer (a sandboxed preview
   *  that strips inline scripts) shows "Verified offline" rather than a stuck
   *  "Verifying"; the embedded script upgrades it to the live in-browser check. */
  readonly verified?: boolean | null;
  readonly merchant: { readonly name: string; readonly host: string; readonly location?: string };
  /** The client-side provenance block from a settle result, or null (a plain
   *  re-fetched receipt carries none, and the provenance section is omitted). */
  readonly provenance?: Record<string, unknown> | null;
  /** A human-facing order link on the merchant's site, or "". */
  readonly orderUrl?: string;
  /** The order's line items, resolved by the caller from order_history +
   *  get_product (name), since the signed receipt carries none. `amount_minor`
   *  is the line's paid amount (unit_price * qty) in minor units when known. */
  readonly items?: ReadonlyArray<{ name: string; sku: string; qty: number; amount_minor?: number }>;
  /** The server-recorded authorization trail from get_signatures: every credential
   *  the Terminal verified for this order (the KYA by hash, the UCP RFC 9421
   *  platform signature, the ERC-3009 payment authorization, the seller offer) plus
   *  Facet's own response-signature chain. Null/absent when the endpoint is
   *  unavailable or the caller could not read it; the trail section is then omitted. */
  readonly serverTrail?:
    | {
      readonly signatures?: ReadonlyArray<Record<string, unknown>>;
      readonly authorizations?: ReadonlyArray<Record<string, unknown>>;
    }
    | null;
  /** Post-settlement reversals for this order (per-line cancel, withdraw, dispute,
   *  refund), rendered as an Amendments section with a Net-now line. The original
   *  signed settlement above is never mutated: each reversal is its own signed
   *  lifecycle receipt, so the page stays fully verifiable. Empty/absent hides the
   *  section. `amount_minor` is the line's reversed amount (minor units) when known;
   *  when every reversal carries one, Net-now = settlement minus their sum. */
  readonly reversals?:
    | ReadonlyArray<{
      readonly kind: "cancel" | "withdraw" | "dispute" | "refund";
      readonly exchange_id?: string;
      readonly sku?: string;
      readonly name?: string;
      readonly amount_minor?: number;
      /** Every signed lifecycle receipt recorded for this reversed line (the cancel
       *  AND its withdraw, a merchant refund, etc.), each a compact Ed25519 JWS
       *  (typ facet-lifecycle+jws) verifiable offline against the merchant JWKS. These
       *  are recorded in the Amendments section so the reversal signatures travel with
       *  the receipt, exactly as the settlement JWS does. */
      readonly signatures?: ReadonlyArray<ReversalSignature>;
    }>
    | null;
}

// ---- small pure helpers ------------------------------------------------------

function b64urlJson(seg: string): Record<string, unknown> {
  const s = seg.replace(/-/g, "+").replace(/_/g, "/");
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

/** HTML-escape text, including quotes so a value is safe in an attribute too. */
function esc(v: unknown): string {
  return String(v ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string,
  );
}

/** JSON for embedding inside a <script>: escape `<` and the JS line/paragraph
 *  separators (U+2028 / U+2029) so the data can never break out of the script
 *  element or a JS string literal. The regex is built from an escaped string. */
function scriptJson(value: unknown): string {
  const unsafe = new RegExp("[<\\u2028\\u2029]", "g");
  return JSON.stringify(value ?? null).replace(
    unsafe,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

function hostOf(u: unknown): string {
  try {
    return new URL(String(u)).host;
  } catch {
    return String(u ?? "");
  }
}

function moneyMinor(minor: unknown, currency: string): string {
  const n = Number(minor);
  if (!Number.isFinite(n)) return "";
  try {
    return (n / 100).toLocaleString("en-US", { style: "currency", currency });
  } catch {
    return `${(n / 100).toFixed(2)} ${currency}`;
  }
}

function shortHex(s: unknown): string {
  const v = String(s ?? "");
  return v.length > 20 ? v.slice(0, 10) + "…" + v.slice(-8) : v;
}

function prettyRail(rail: string): string {
  return ({
    "coin/boson-escrow": "Boson escrow",
    "coin/usdc-base": "x402 direct",
    "coin/usdc-base-sepolia": "x402 direct",
  } as Record<string, string>)[rail] ?? (rail || "settlement");
}

const NONE = "(none)";
const kvRow = (dt: string, ddHtml: string): string => `<dt>${esc(dt)}</dt><dd>${ddHtml}</dd>`;

// ---- section builders --------------------------------------------------------

function chipsHtml(st: Record<string, unknown>): string {
  const live = st.livemode === true;
  return [
    `<span class="chip">${esc(prettyRail(String(st.rail ?? "")))}</span>`,
    `<span class="chip ok">${live ? "Live" : "Test"} &#183; ${live ? "Base mainnet" : "Base Sepolia"}</span>`,
    `<span class="chip">USDC</span>`,
  ].join("\n        ");
}

/** The money breakdown (goods / tax / shipping / duty / discount), from the JWS
 *  split. Rendered as a definition list in the amount-detail block. */
function breakdownHtml(split: Record<string, unknown> | undefined, currency: string): string {
  const rows: Array<[string, string]> = [
    ["Goods", "goods_minor"],
    ["Tax", "tax_minor"],
    ["Shipping", "shipping_minor"],
    ["Duty", "duty_minor"],
    ["Discount", "discount_minor"],
  ];
  const parts: string[] = [];
  for (const [label, key] of rows) {
    if (split && split[key] !== undefined) {
      parts.push(`<dt>${label}</dt><dd>${esc(moneyMinor(split[key], currency))}</dd>`);
    }
  }
  return parts.join("\n          ");
}

/** The Amendments section: post-settlement reversals for this order (one entry per
 *  reversed LINE; the caller folds a cancel + its withdraw into a single line so the
 *  amount is not double-counted), plus a Net-now line. The original signed settlement
 *  above is never mutated. Each reversal is its own signed lifecycle receipt, so the
 *  page stays fully verifiable. Returns "" (section hidden) when there are none.
 *  Net-now renders ONLY when every reversal carries an amount, since a partial sum
 *  would show a wrong total, which is worse than none. */
function amendmentsHtml(
  reversals: ReceiptRenderInput["reversals"],
  settlementAmountMinor: unknown,
  currency: string,
): string {
  const list = Array.isArray(reversals) ? reversals : [];
  if (list.length === 0) return "";
  const verb: Record<string, string> = {
    cancel: "cancelled",
    withdraw: "cashed out",
    dispute: "disputed",
    refund: "refunded",
  };
  const items = list
    .map((r) => {
      const label = r.name && r.name !== "" ? r.name : (r.sku ?? `exchange ${r.exchange_id ?? ""}`);
      const skuPart = r.sku && r.name ? ` (${esc(r.sku)})` : "";
      const act = verb[r.kind] ?? esc(r.kind);
      const amt = typeof r.amount_minor === "number"
        ? `<span class="rev-amt">-${esc(moneyMinor(r.amount_minor, currency))}</span>`
        : "";
      // The recorded signatures for this reversal (the cancel AND its withdraw, a
      // merchant refund, etc.): each a compact JWS embedded in the page so the proof
      // travels with the receipt and can be verified offline against the merchant JWKS.
      const sigs: readonly ReversalSignature[] = r.signatures ?? [];
      const sigHtml = sigs
        .map((s) => {
          const sVerb = verb[s.kind] ?? esc(s.kind);
          const tx = s.tx_hash && s.tx_hash !== "" ? ` &#183; ${esc(shortHex(s.tx_hash))}` : "";
          const ok = s.verified === true ? ` &#183; <span class="rev-ok">verified</span>` : "";
          return `<details class="rev-sig">
              <summary>${sVerb} signature${tx}${ok}</summary>
              <code class="rev-jws">${esc(s.jws)}</code>
            </details>`;
        })
        .join("\n            ");
      const sigBlock = sigHtml !== "" ? `\n            ${sigHtml}` : "";
      return `<li>
          <div class="rev-row"><span class="rev-what">${esc(label)}${skuPart} ${act}</span>${amt}</div>${sigBlock}
        </li>`;
    })
    .join("\n        ");
  const total = Number(settlementAmountMinor);
  const allAmounts = list.every((r) => typeof r.amount_minor === "number");
  const sum = list.reduce((a, r) => a + (typeof r.amount_minor === "number" ? r.amount_minor : 0), 0);
  const netRow = allAmounts && Number.isFinite(total)
    ? `\n        <div class="net-now"><span>Net now</span><span>${
      esc(moneyMinor(total - sum, currency))
    }</span></div>`
    : "";
  return `<div class="amendments">
        <h3 class="lbl">Amendments</h3>
        <ul class="rev-list">
        ${items}
        </ul>${netRow}
      </div>`;
}

/** The order items, resolved by the caller (name, sku, qty, and the paid line
 *  amount). When none are available (a receipt fetched without the order), a
 *  short note stands in so the column is never empty. */
function itemsHtml(
  items: ReadonlyArray<{ name: string; sku: string; qty: number; amount_minor?: number }> | undefined,
  currency: string,
): string {
  if (!items || items.length === 0) {
    return `<div class="item-meta">Line items are not available for this order; the money breakdown is on the right.</div>`;
  }
  return items.map((it, i) => {
    const n = String(i + 1).padStart(2, "0");
    const amt = typeof it.amount_minor === "number"
      ? `<span class="item-amt">${esc(moneyMinor(it.amount_minor, currency))}</span>`
      : "";
    return `<div class="item">
          <span class="item-n">${n}</span>
          <div class="item-body">
            <div class="item-top"><span class="item-desc">${esc(it.name)}</span>${amt}</div>
            <div class="item-meta">${esc(it.sku)} &#183; Qty ${esc(it.qty)}</div>
          </div>
        </div>`;
  }).join("\n        ");
}

function settlementKv(claims: Record<string, unknown>, st: Record<string, unknown>): string {
  const rail = String(st.rail ?? "");
  const rows = [
    kvRow("Order", esc(claims.jti ?? NONE)),
    st.settlement_id
      ? kvRow("Escrow", esc((rail === "coin/boson-escrow" ? "Boson exchange " : "settlement ") + st.settlement_id))
      : "",
    kvRow("Rail", esc(rail || NONE)),
    kvRow("Settled", esc(st.settled_at ?? NONE)),
    kvRow("Livemode", st.livemode === true ? "true &#183; real USDC on Base" : "false &#183; testnet"),
  ];
  return rows.filter((r) => r !== "").join("\n        ");
}

function signedbyKv(claims: Record<string, unknown>, header: Record<string, unknown>, jwksUrl: string): string {
  const iss = String(claims.iss ?? "");
  const iat = typeof claims.iat === "number"
    ? `${claims.iat} &#183; ${new Date(claims.iat * 1000).toISOString().replace("T", " ").replace(/\..+/, " UTC")}`
    : NONE;
  const rows = [
    kvRow(
      "Issuer",
      iss ? `<a href="${esc(iss)}" target="_blank" rel="noopener">${esc(hostOf(iss))}</a>` : NONE,
    ),
    kvRow("Key (kid)", esc(header.kid ?? NONE)),
    kvRow("Alg / typ", esc(`${header.alg ?? "EdDSA"} &#183; ${header.typ ?? "facet-receipt+jws"}`).replace("&amp;#183;", "&#183;")),
    claims.sub ? kvRow("Subject", esc(claims.sub)) : "",
    kvRow("Signed", iat),
    kvRow("JWKS", `<a href="${esc(jwksUrl)}" target="_blank" rel="noopener">/.well-known/jwks.json</a>`),
  ];
  return rows.filter((r) => r !== "").join("\n        ");
}

/** The identity + payment provenance block, in the template's own section style,
 *  or "" when there is no provenance (a plain re-fetched receipt). */
function provenanceSection(provenance: Record<string, unknown> | null | undefined): string {
  if (provenance === null || provenance === undefined || typeof provenance !== "object") return "";
  const id = provenance.identity as { aid?: string; issuer?: string; expires?: number } | undefined;
  const pay = provenance.payment as Record<string, unknown> | undefined;
  if (!id && !pay) return "";

  const idRows: string[] = [];
  if (id) {
    idRows.push(kvRow("Agent (aid)", esc(id.aid ?? NONE)));
    idRows.push(
      kvRow(
        "Issuer",
        id.issuer ? `<a href="${esc(id.issuer)}" target="_blank" rel="noopener">${esc(hostOf(id.issuer))}</a>` : NONE,
      ),
    );
    if (id.expires) {
      idRows.push(kvRow("KYA exp", esc(new Date(id.expires * 1000).toISOString().slice(0, 10))));
    }
  }

  const payRows: string[] = [];
  if (pay) {
    const railName = pay.rail === "boson" ? "Boson escrow" : (pay.rail === "mpp" ? "MPP evm/charge" : "x402 direct");
    payRows.push(kvRow("Rail", esc(railName)));
    const ta = (pay.token_authorization ?? pay.authorization) as
      | { from?: string; to?: string; value?: string; nonce?: string }
      | undefined;
    if (ta) {
      if (ta.value) payRows.push(kvRow("Authorizes", esc(`${Number(ta.value) / 1e6} USDC`)));
      if (ta.from && ta.to) payRows.push(kvRow("From to", `${esc(shortHex(ta.from))} &#8594; ${esc(shortHex(ta.to))}`));
      if (ta.nonce) payRows.push(kvRow("Nonce", esc(shortHex(ta.nonce))));
    }
    const sig = pay.buyer_signature as { v?: number; r?: string; s?: string } | undefined;
    if (sig && typeof sig === "object") {
      payRows.push(kvRow("Buyer sig", esc(`v${sig.v} r ${shortHex(sig.r)}`)));
    } else if (typeof pay.signature === "string") {
      payRows.push(kvRow("Buyer sig", esc(shortHex(pay.signature))));
    }
    if (typeof pay.seller_signature === "string") payRows.push(kvRow("Seller sig", esc(shortHex(pay.seller_signature))));
    if (typeof pay.escrow === "string") payRows.push(kvRow("Escrow", esc(shortHex(pay.escrow))));
    else if (typeof pay.pay_to === "string") payRows.push(kvRow("Pays", esc(shortHex(pay.pay_to))));
  }

  const cols: string[] = [];
  if (idRows.length > 0) {
    cols.push(`<div>\n      <h2 class="lbl">Buyer identity</h2>\n      <dl class="kv">\n        ${idRows.join("\n        ")}\n      </dl>\n    </div>`);
  }
  if (payRows.length > 0) {
    cols.push(`<div>\n      <h2 class="lbl">Payment authorization</h2>\n      <dl class="kv">\n        ${payRows.join("\n        ")}\n      </dl>\n    </div>`);
  }
  return `<div class="pad div meta">\n    ${cols.join("\n    ")}\n  </div>`;
}

function ledgerHtml(chain: { this_hash?: string; prev_hash?: string } | undefined): string {
  if (!chain || !chain.this_hash) return "";
  return `<div class="pad div">
    <h2 class="lbl" style="margin-bottom:10px">Tamper-evident ledger</h2>
    <div class="ledger">
      <div class="hash"><div class="h">Prev entry</div><code>${esc(chain.prev_hash ?? "(genesis)")}</code></div>
      <div class="arw" aria-hidden="true">&#8594;</div>
      <div class="hash"><div class="h">This order</div><code>${esc(chain.this_hash)}</code></div>
    </div>
    <p class="note">Each settlement links to the one before it by hash, so no entry can be altered or reordered without breaking the chain. This receipt anchors to the newest link; countersignatures accrue over time.</p>
  </div>`;
}

/** A human label for an order_authorizations kind. */
function authKindLabel(kind: string): string {
  switch (kind) {
    case "kya":
      return "Buyer KYA";
    case "kya_owner":
      return "Owner KYA";
    case "kya_buyer":
      return "Buyer KYA";
    case "ucp_platform_rfc9421":
      return "Platform signature";
    case "x402_buyer_erc3009":
      return "Payment authorization";
    case "boson_seller_offer":
      return "Seller offer";
    case "autonomous_delegation":
      return "Delegated authority";
    default:
      return kind;
  }
}

/** The full server-recorded authorization trail from get_signatures: one row per
 *  credential the Terminal verified for this order (the KYA by hash, the UCP RFC
 *  9421 platform signature, the ERC-3009 payment authorization, the seller offer,
 *  a delegation) plus a one-line summary of Facet's own response-signature chain.
 *  Reuses the same kv/section style as the client provenance block. "" when there
 *  is no trail (the endpoint was unavailable or returned nothing). */
function serverTrailSection(
  trail:
    | {
      signatures?: ReadonlyArray<Record<string, unknown>>;
      authorizations?: ReadonlyArray<Record<string, unknown>>;
    }
    | null
    | undefined,
): string {
  if (!trail || typeof trail !== "object") return "";
  const auths = Array.isArray(trail.authorizations) ? trail.authorizations : [];
  const sigs = Array.isArray(trail.signatures) ? trail.signatures : [];
  if (auths.length === 0 && sigs.length === 0) return "";

  const authRows = auths.map((a) => {
    const kind = typeof a.kind === "string" ? a.kind : "";
    const leg = typeof a.leg === "string" ? a.leg : "";
    const verification = typeof a.verification === "string" ? a.verification : "";
    const label = `${authKindLabel(kind)}${leg !== "" ? ` (${leg})` : ""}`;
    // The evidence per row: a KYA by its sha256; the platform signature by its
    // authenticated origin; every other credential by a short of its verbatim
    // artifact; else the verified subject. Regulated identity is never shown.
    let ev = "";
    if (kind === "kya" || kind === "kya_owner" || kind === "kya_buyer") {
      const h = typeof a.artifact_sha256 === "string" ? a.artifact_sha256 : "";
      ev = h !== "" ? `sha256 ${shortHex(h)}` : (typeof a.subject_ref === "string" ? shortHex(a.subject_ref) : "");
    } else if (kind === "ucp_platform_rfc9421") {
      ev = typeof a.profile_origin === "string" && a.profile_origin !== "" ? hostOf(a.profile_origin) : "RFC 9421";
    } else if (typeof a.artifact === "string" && a.artifact !== "") {
      ev = shortHex(a.artifact);
    } else if (typeof a.subject_ref === "string") {
      ev = shortHex(a.subject_ref);
    }
    const dd = `<code>${esc(ev !== "" ? ev : NONE)}</code>${verification !== "" ? ` &#183; ${esc(verification)}` : ""}`;
    return kvRow(esc(label), dd);
  });

  const facetSigs = sigs.filter((s) => s.party === "facet").length;
  const attestations = sigs.filter((s) => s.party !== "facet").length;
  const summaryBits: string[] = [];
  if (facetSigs > 0) {
    summaryBits.push(`${facetSigs} Facet Ed25519 response ${facetSigs === 1 ? "signature" : "signatures"}`);
  }
  if (attestations > 0) {
    summaryBits.push(`${attestations} counterparty ${attestations === 1 ? "attestation" : "attestations"}`);
  }

  const parts: string[] = [
    `<h2 class="lbl">Authorization trail</h2>`,
    `<p class="note" style="margin-top:0">Every credential the Terminal verified across this purchase, from its own signature ledger. The KYA is shown by hash; regulated identity is never returned.</p>`,
  ];
  if (authRows.length > 0) {
    parts.push(`<dl class="kv">\n        ${authRows.join("\n        ")}\n      </dl>`);
  }
  if (summaryBits.length > 0) {
    parts.push(`<p class="note">Ledger: ${esc(summaryBits.join(", "))}.</p>`);
  }
  return `<div class="pad div">\n      ${parts.join("\n      ")}\n    </div>`;
}

// ---- the fill ----------------------------------------------------------------

/** Fill the official template with a receipt's fields, rendered server-side.
 *  Pure: the template string in, the finished HTML out. Throws if the template is
 *  missing an expected token (a wrong or truncated template). */
export function fillReceiptTemplate(template: string, input: ReceiptRenderInput): string {
  const [hSeg, pSeg, sSeg] = input.jws.split(".");
  const header = b64urlJson(hSeg ?? "");
  const claims = b64urlJson(pSeg ?? "");
  const st = (claims.settlement ?? {}) as Record<string, unknown>;
  const currency = String(st.currency ?? "USD");
  const iss = String(claims.iss ?? "");
  const jwksUrl = `${iss.replace(/\/$/, "")}/.well-known/jwks.json`;
  const amountFull = moneyMinor(st.amount_minor, currency);
  const amountNum = amountFull.replace(/^[^0-9-]+/, "");

  const tokens: Record<string, string> = {
    "%%AMOUNT_CUR%%": esc(currency),
    "%%AMOUNT%%": esc(amountNum),
    "%%CHIPS%%": chipsHtml(st),
    "%%ITEMS%%": itemsHtml(input.items, currency),
    "%%BREAKDOWN%%": breakdownHtml(claims.split as Record<string, unknown> | undefined, currency),
    "%%AMENDMENTS%%": amendmentsHtml(input.reversals, st.amount_minor, currency),
    "%%PROVENANCE%%": provenanceSection(input.provenance),
    "%%SETTLEMENT_KV%%": settlementKv(claims, st),
    "%%SIGNEDBY_KV%%": signedbyKv(claims, header, jwksUrl),
    "%%SERVER_TRAIL%%": serverTrailSection(input.serverTrail),
    "%%LEDGER%%": ledgerHtml(claims.chain as { this_hash?: string; prev_hash?: string } | undefined),
    "%%ORDER_HREF%%": esc(input.orderUrl ?? ""),
    "%%JWKS_HREF%%": esc(jwksUrl),
    "%%RECEIPT_SHORT%%": esc(String(claims.jti ?? "").slice(0, 8)),
    "%%MERCHANT_HOST%%": esc(hostOf(iss)),
    "%%JWS%%": scriptJson(input.jws),
    "%%PUBKEY_X%%": scriptJson(input.pubkeyX),
    // Server-rendered so the decoded header/payload show even when the viewer
    // strips inline scripts (a sandboxed preview); the embedded script overwrites
    // them with the same content when it runs.
    "%%HDR_JSON%%": esc(JSON.stringify(header, null, 2)),
    "%%CLAIMS_JSON%%": esc(JSON.stringify(claims, null, 2)),
    // The seal's static resting state from the render-time offline verdict. JS
    // upgrades it to the live in-browser Ed25519 check, or flips it to Invalid.
    "%%SEAL_CLASS%%": input.verified === true ? "stamp is-ok" : "stamp is-checking",
    "%%SEAL_WORD%%": input.verified === true ? "Verified" : "Verifying",
    "%%SEAL_STATUS%%": input.verified === true
      ? "offline against the merchant JWKS"
      : "Ed25519, in your browser",
    // Server-rendered so the compact JWS and the JOSE reproduce snippet show even
    // in a no-JS viewer, symmetric with the decoded header/payload above; the
    // inline script overwrites both with the same content when it runs.
    "%%JWS_SPANS%%": `<span class="sh">${esc(hSeg ?? "")}</span><span class="dt">.</span>` +
      `<span class="sp">${esc(pSeg ?? "")}</span><span class="dt">.</span>` +
      `<span class="ss">${esc(sSeg ?? "")}</span>`,
    "%%SNIPPET%%": esc(
      `import { compactVerify, createLocalJWKSet } from "jose";\n\n` +
        `const origin = ${JSON.stringify(iss || "")};\n` +
        `const jwks = await (await fetch(origin + "/.well-known/jwks.json")).json();\n` +
        `const { payload } = await compactVerify(jws, createLocalJWKSet(jwks));\n\n` +
        `// throws unless typ = facet-receipt+jws, alg = EdDSA,\n` +
        `// iss = the origin you transacted with, and the signature checks out.\n` +
        `console.log("verified:", JSON.parse(new TextDecoder().decode(payload)));`,
    ),
  };

  let html = template;
  for (const [token, value] of Object.entries(tokens)) {
    if (!html.includes(token)) throw new Error(`receipt template is missing the ${token} token.`);
    html = html.replaceAll(token, value);
  }
  // The order button is hidden when there is no order url.
  html = html.replaceAll("%%ORDER_HIDDEN%%", (input.orderUrl ?? "") === "" ? " hidden" : "");
  return html;
}

/** Extract the Ed25519 public key (`x`) that matches `kid` from a merchant JWKS,
 *  so the rendered page can verify the signature in the browser. Prefers an
 *  exact kid match; falls back to the sole Ed25519 key when the JWKS has one and
 *  the kid did not match. Returns null when no Ed25519 key is present. Pure. */
export function pubkeyXForKid(jwks: unknown, kid: string): string | null {
  const keys = (jwks as { keys?: unknown[] } | null)?.keys;
  if (!Array.isArray(keys)) return null;
  const ed = (k: unknown): k is { x: string; kid?: string } => {
    const key = k as { kty?: string; crv?: string; x?: unknown };
    return key !== null && typeof key === "object" && key.kty === "OKP" && key.crv === "Ed25519" &&
      typeof key.x === "string";
  };
  for (const k of keys) if (ed(k) && (k as { kid?: string }).kid === kid) return k.x;
  const eds = keys.filter(ed);
  return eds.length === 1 ? eds[0].x : null;
}

/** A readable merchant name from a Terminal host, when no explicit name is
 *  given: title-case the leading label (pecanandpetal.facet.llc becomes
 *  "Pecanandpetal"). Callers should prefer an explicit --merchant-name. Pure. */
export function merchantNameFromHost(host: string): string {
  const label = String(host || "").split(".")[0] || String(host || "");
  if (label === "") return String(host || "");
  return label.charAt(0).toUpperCase() + label.slice(1);
}
