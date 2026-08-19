// Self-serve, wallet-bound KYA provisioning against issuer.facet.llc, with NO
// service key. The agent enrolls a fresh P-256 identity (proof-of-possession at
// POST /v1/enroll), presents a private_key_jwt client_assertion from it, and
// EIP-191 signs a domain-separated wallet-binding challenge with the buyer
// wallet; the issuer recovers the signer, requires it to equal the claimed
// wallet, consumes the challenge single-use, and mints a KYA carrying the
// payer_wallet claim (ready for a store's dual auth).
//
// Safe to ship in a public skill: it embeds NO Facet secret. The wallet key
// signs locally and never leaves the process; authentication is the buyer's own
// client_assertion plus the wallet proof, not an issuer service key. The endpoint
// is the already-public, rate-limited self-serve path, so this client reaches
// nothing an attacker could not already reach. The minted KYA is a bearer token:
// it is cached to a mode-600 file and returned to the caller, never printed.
import { generateKeyPair, exportJWK, calculateJwkThumbprint, SignJWT } from "npm:jose@5.9.6";
import { privateKeyToAccount } from "npm:viem@2.50.4/accounts";

export const DEFAULT_ISSUER = (Deno.env.get("FACET_ISSUER_URL") ?? "https://issuer.facet.llc").replace(/\/+$/, "");
export const DEFAULT_KYA_AUDIENCE = Deno.env.get("FACET_KYA_AUDIENCE") ?? "https://facet.llc/v1";
// Issuers whose KYAs this client will use without re-minting. Defaults to the
// Facet issuer; override for a private issuer. A KYA from any other issuer is
// treated as untrusted and skipped, so a stale token never blocks a checkout.
export const TRUSTED_KYA_ISSUERS = (Deno.env.get("FACET_TRUSTED_KYA_ISSUERS") ?? DEFAULT_ISSUER)
  .split(",").map((s) => s.trim()).filter((s) => s !== "");
const CACHE_DIR = Deno.env.get("FACET_KYA_CACHE_DIR") ?? `${Deno.env.get("HOME") ?? "."}/.cache/facet`;

export interface KyaClaims {
  iss?: string;
  exp?: number;
  aid?: string;
  aud?: string;
  payer_wallet?: string;
}

export function kyaClaims(token: string): KyaClaims {
  try {
    const p = token.split(".");
    if (p.length < 2) return {};
    return JSON.parse(atob(p[1].replace(/-/g, "+").replace(/_/g, "/"))) as KyaClaims;
  } catch {
    return {};
  }
}

// A KYA is usable when it is unexpired (30s buffer) and from a trusted issuer,
// and, when an address is supplied, bound to that wallet. Untrusted or expired
// tokens are skipped so a stale FACET_KYA never blocks a checkout.
export function kyaUsable(token: string | undefined, address?: string): boolean {
  if (!token) return false;
  const c = kyaClaims(token);
  const now = Math.floor(Date.now() / 1000);
  if (typeof c.exp === "number" && c.exp <= now + 30) return false;
  if (c.iss !== undefined && !TRUSTED_KYA_ISSUERS.includes(c.iss)) return false;
  if (address && c.payer_wallet && c.payer_wallet.toLowerCase() !== address.toLowerCase()) return false;
  return true;
}

export function cachePathFor(key: string): string {
  return `${CACHE_DIR}/kya-${key.replace(/[^a-zA-Z0-9._-]/g, "_")}.jwt`;
}

export function readCachedKya(key: string): string | undefined {
  try {
    const t = Deno.readTextFileSync(cachePathFor(key)).trim();
    return t || undefined;
  } catch {
    return undefined;
  }
}

// Mint a fresh wallet-bound KYA. `walletKey` signs locally and is never
// transmitted. Returns { token, claims } and caches the token to a mode-600 file
// keyed by `cacheKey` (default the wallet address). Throws on any failure.
export async function provisionKya(
  walletKey: string,
  opts: { issuer?: string; audience?: string; cacheKey?: string } = {},
): Promise<{ token: string; claims: KyaClaims }> {
  const issuer = (opts.issuer ?? DEFAULT_ISSUER).replace(/\/+$/, "");
  const audience = opts.audience ?? DEFAULT_KYA_AUDIENCE;
  const account = privateKeyToAccount(walletKey as `0x${string}`);
  const now = Math.floor(Date.now() / 1000);

  // 1. Fresh P-256 identity + its aid (RFC 7638 thumbprint).
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const pubJwk = await exportJWK(publicKey);
  const thumb = await calculateJwkThumbprint(pubJwk, "sha256");
  let aid = `facet:agent:${thumb}`;

  // 2. Enroll the identity key (proof-of-possession JWS).
  const proof = await new SignJWT({ purpose: "enroll", jti: crypto.randomUUID() })
    .setProtectedHeader({ alg: "ES256" }).setAudience(issuer).setIssuedAt(now).sign(privateKey);
  const er = await fetch(`${issuer}/v1/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ public_jwk: pubJwk, proof }),
  });
  const eb = (await er.json().catch(() => ({}))) as Record<string, unknown>;
  if (er.status < 200 || er.status >= 300) {
    throw new Error(`enrollment failed HTTP ${er.status}: ${JSON.stringify(eb).slice(0, 200)}`);
  }
  if (typeof eb.aid === "string") aid = eb.aid;

  // 3. client_assertion (self-issued private_key_jwt) authenticates the mint.
  const assertion = await new SignJWT({ jti: crypto.randomUUID() })
    .setProtectedHeader({ alg: "ES256", kid: aid })
    .setIssuer(aid).setSubject(aid).setAudience(issuer)
    .setIssuedAt(now).setExpirationTime(now + 120).sign(privateKey);

  // 4. Wallet proof-of-control (EIP-191).
  const challenge = crypto.randomUUID();
  const message = `Facet wallet binding\naid: ${aid}\nwallet: ${account.address}\nnonce: ${challenge}`;
  const wallet_signature = await account.signMessage({ message });

  // 5. Mint the wallet-bound KYA.
  const mr = await fetch(`${issuer}/v1/wallet-tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_assertion: assertion,
      aid,
      audience,
      payer_wallet: account.address,
      wallet_challenge: challenge,
      wallet_signature,
    }),
  });
  const mb = (await mr.json().catch(() => ({}))) as Record<string, unknown>;
  if (mr.status < 200 || mr.status >= 300 || typeof mb.token !== "string") {
    throw new Error(`KYA mint failed HTTP ${mr.status}: ${JSON.stringify(mb).slice(0, 200)}`);
  }
  const token = mb.token as string;

  const cacheKey = opts.cacheKey ?? account.address;
  try {
    Deno.mkdirSync(CACHE_DIR, { recursive: true });
    Deno.writeTextFileSync(cachePathFor(cacheKey), token);
    Deno.chmodSync(cachePathFor(cacheKey), 0o600);
  } catch {
    // Cache is best-effort; the token is still returned for immediate use.
  }
  return { token, claims: kyaClaims(token) };
}
