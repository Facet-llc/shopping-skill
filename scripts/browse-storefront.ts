// browse-storefront.ts
// LAST-RESORT fallback reader for the shopping skill. Primary discovery is the
// client's own native browser on the merchant's real storefront, or the
// Terminal's given-not-scraped `search`. This script exists only for the case
// where neither is available: it reads a merchant's PUBLIC, human-facing
// storefront and returns a lean, normalized product list the agent can show as
// a short text list and carry SKUs from. It rebuilds nothing and renders no
// panel. Reading the public store needs no identity, no wallet, and no secrets,
// so this script never touches FACET_KYA or FACET_WALLET_KEY and asks only for
// --allow-net. The Facet Terminal is never called here.
//
// The product SKU is the join key to the Terminal at buy time (a WooCommerce
// `sku` is the same string as the Terminal product `id`).
//
// Usage:
//   deno run --allow-net browse-storefront.ts --site <host> [--query q] [--limit n]
//
// Prints ONE JSON object to stdout:
//   { ok, source, store, count, total, products: [ {
//       sku, name, price, regular, currency, on_sale, in_stock,
//       short, url, img_url, img_full } ] }
//
// img_url / img_full are remote image URLs on the merchant's own host, kept for
// reference only; this script does not fetch, inline, or render them.

interface Product {
  sku: string | null;
  name: string;
  price: number | null;
  regular: number | null;
  currency: string;
  on_sale: boolean;
  in_stock: boolean;
  short: string;
  url: string | null;
  img_url: string | null;
  img_full: string | null;
}

function flag(name: string): string | undefined {
  const i = Deno.args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < Deno.args.length ? Deno.args[i + 1] : undefined;
}

function emit(obj: unknown): never {
  console.log(JSON.stringify(obj));
  Deno.exit(0);
}

function stripHtml(s: string | null | undefined): string {
  if (!s) return "";
  return s
    .replace(/<[^>]+>/g, "")
    // numeric HTML entities (decimal and hex), e.g. &#038; -> &, &#x27; -> '
    .replace(/&#(\d+);/g, (_m, n) => {
      try {
        return String.fromCodePoint(parseInt(n, 10));
      } catch {
        return _m;
      }
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, n) => {
      try {
        return String.fromCodePoint(parseInt(n, 16));
      } catch {
        return _m;
      }
    })
    // common named entities
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normHost(raw: string): string {
  const h = raw.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return `https://${h}`;
}

const UA = "Mozilla/5.0 (compatible; FacetShoppingAgent/1.0)";

async function getJson(url: string): Promise<unknown | null> {
  try {
    const r = await fetch(url, {
      headers: { "user-agent": UA, "accept": "application/json" },
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function getText(url: string): Promise<string | null> {
  try {
    const r = await fetch(url, { headers: { "user-agent": UA } });
    if (!r.ok) return null;
    return await r.text();
  } catch {
    return null;
  }
}

// deno-lint-ignore no-explicit-any
function smallestSrc(img: any): string | null {
  if (!img) return null;
  const srcset: string = img.srcset || "";
  let best: { url: string; w: number } | null = null;
  for (const part of srcset.split(",")) {
    const m = part.trim().match(/^(\S+)\s+(\d+)w$/);
    if (m) {
      const w = parseInt(m[2], 10);
      if (!best || w < best.w) best = { url: m[1], w };
    }
  }
  return best?.url || img.thumbnail || img.src || null;
}

// deno-lint-ignore no-explicit-any
function minorToNum(v: any, minor: number): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n / Math.pow(10, minor) : null;
}

// Path 1: WooCommerce Store API (public, no auth). The clean source for any
// Woo-backed merchant: real images, prices, sale flags, stock, and the SKU.
async function tryWoo(base: string): Promise<Product[] | null> {
  for (
    const path of [
      "/wp-json/wc/store/v1/products?per_page=100",
      "/wp-json/wc/store/products?per_page=100",
    ]
  ) {
    const data = await getJson(base + path);
    if (Array.isArray(data) && data.length) {
      // deno-lint-ignore no-explicit-any
      return data.map((p: any) => {
        const pr = p.prices || {};
        const minor = pr.currency_minor_unit ?? 2;
        const img0 = (p.images || [])[0] || null;
        return {
          sku: p.sku || null,
          name: stripHtml(p.name) || "(unnamed)",
          price: minorToNum(pr.price, minor),
          regular: minorToNum(pr.regular_price, minor),
          currency: pr.currency_code || "USD",
          on_sale: !!p.on_sale,
          in_stock: p.is_in_stock !== false,
          short: stripHtml(p.short_description || p.description),
          url: p.permalink || null,
          img_url: smallestSrc(img0),
          img_full: (img0 && (img0.src || img0.thumbnail)) || null,
        } as Product;
      });
    }
  }
  return null;
}

// deno-lint-ignore no-explicit-any
function firstImage(image: any): string | null {
  if (!image) return null;
  if (typeof image === "string") return image;
  if (Array.isArray(image)) return firstImage(image[0]);
  if (typeof image === "object") return image.url || image.contentUrl || null;
  return null;
}

// Path 2: generic JSON-LD Product structured data, the fallback for a
// non-WooCommerce storefront (many platforms emit this). Best-effort.
function ldProducts(html: string): Product[] {
  const products: Product[] = [];
  // deno-lint-ignore no-explicit-any
  const nodes: any[] = [];
  const re =
    /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      const j = JSON.parse(m[1].trim());
      if (Array.isArray(j)) nodes.push(...j);
      else if (j["@graph"]) nodes.push(...j["@graph"]);
      else nodes.push(j);
    } catch {
      // skip malformed blocks
    }
  }
  for (const n of nodes) {
    const t = n && (n["@type"] || "");
    const isProduct = t === "Product" ||
      (Array.isArray(t) && t.includes("Product"));
    if (!isProduct) continue;
    const offers = Array.isArray(n.offers) ? n.offers[0] : n.offers;
    const price = offers ? Number(offers.price ?? offers.lowPrice) : NaN;
    const avail = (offers && offers.availability) || "";
    products.push({
      sku: n.sku || n.mpn || null,
      name: stripHtml(n.name) || "(unnamed)",
      price: Number.isFinite(price) ? price : null,
      regular: null,
      currency: (offers && offers.priceCurrency) || "USD",
      on_sale: false,
      in_stock: !avail || /InStock/i.test(avail),
      short: stripHtml(n.description),
      url: (offers && offers.url) || n.url || null,
      img_url: firstImage(n.image),
      img_full: firstImage(n.image),
    });
  }
  return products;
}

const siteArg = flag("site") || flag("store-url");
if (!siteArg) emit({ ok: false, error: "missing --site <host>" });
const base = normHost(siteArg!);
const query = (flag("query") || "").toLowerCase();
const limit = parseInt(flag("limit") || "60", 10);

let source = "woocommerce";
let products = await tryWoo(base);
if (!products) {
  const html = await getText(base + "/");
  if (html) {
    products = ldProducts(html);
    source = "jsonld";
  }
}
if (!products || !products.length) {
  emit({
    ok: false,
    store: base,
    error: "no public catalog found (tried WooCommerce Store API and JSON-LD)",
  });
}

let matched = products!;
if (query) {
  matched = matched.filter((p) =>
    p.name.toLowerCase().includes(query) ||
    p.short.toLowerCase().includes(query)
  );
}
const total = matched.length;
const list = matched.slice(0, Math.max(1, limit));

emit({
  ok: true,
  source,
  store: base,
  count: list.length,
  total,
  products: list,
});
