// order-prefs.ts : non-secret buyer order preferences for the shopping skill.
//
// Holds the buyer's throwaway shipping-email choice so the shopping agent asks
// ONCE, on the first purchase, then reuses the answer on every order after and
// never asks again. This is a PREFERENCE, not a secret: it lives as plain JSON
// under ~/.cache/facet (the same --allow-write="$HOME/.cache" grant the skill
// already uses for the cached KYA), NEVER under ~/.facet (the encrypted keystore,
// which is only for keys). The stored email is buyer-provided; a Facet-generated
// relay alias is a future follow-up, not built here.
//
// File shape (order-prefs.json):
//   { "shippingEmail": { "optedIn": boolean, "address": string | null } }
//
// An absent file (or an absent shippingEmail key) means "never asked": buy then
// surfaces shipping_email_pref: "unset" so the agent knows to ask before it
// settles. The address only ever lands on order_attributes.contact_email and
// authorizes nothing on the money path.

export interface ShippingEmailPref {
  optedIn: boolean;
  address: string | null;
}

export interface OrderPrefs {
  shippingEmail?: ShippingEmailPref;
}

// The signal `buy` prints so the agent knows the preference state without having
// to read the file itself:
//   "unset"     never asked; the agent should ask before settling.
//   "opted_in"  a stored throwaway address is on this order.
//   "opted_out" the buyer declined; attach nothing and do not ask again.
//   "override"  a one-shot --shipping-email was used; the stored default is
//               left unchanged.
export type ShippingEmailSignal = "unset" | "opted_in" | "opted_out" | "override";

// The preferences file path, env-overridable so a test can point it at a temp
// dir without touching the real cache. Resolved per call (not at module load) so
// a test that sets the env var after import still takes effect. FACET_ORDER_PREFS_FILE
// pins an exact path; otherwise the file sits in FACET_ORDER_PREFS_DIR (or the
// default ~/.cache/facet).
export function orderPrefsFile(): string {
  const explicit = Deno.env.get("FACET_ORDER_PREFS_FILE");
  if (explicit !== undefined && explicit !== "") return explicit;
  const dir = Deno.env.get("FACET_ORDER_PREFS_DIR") ?? `${Deno.env.get("HOME") ?? "."}/.cache/facet`;
  return `${dir}/order-prefs.json`;
}

// Read the preferences file. An absent or unreadable file, or malformed JSON, is
// treated as "no preferences recorded" (an empty object), never a throw: a
// corrupt file must not break a checkout, it just means the agent asks again.
export function readOrderPrefs(file: string = orderPrefsFile()): OrderPrefs {
  let text: string;
  try {
    text = Deno.readTextFileSync(file);
  } catch {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {};
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const obj = parsed as Record<string, unknown>;
  const out: OrderPrefs = {};
  const se = obj.shippingEmail;
  if (se !== null && typeof se === "object" && !Array.isArray(se)) {
    const seo = se as Record<string, unknown>;
    const optedIn = seo.optedIn === true;
    const address = typeof seo.address === "string" && seo.address !== "" ? seo.address : null;
    out.shippingEmail = { optedIn, address };
  }
  return out;
}

// Write the preferences file, creating the parent directory as needed. Pretty
// printed with a trailing newline so a human can read it.
export function writeOrderPrefs(prefs: OrderPrefs, file: string = orderPrefsFile()): void {
  const dir = file.replace(/\/[^/]*$/, "");
  if (dir !== "" && dir !== file) {
    try {
      Deno.mkdirSync(dir, { recursive: true });
    } catch {
      // The directory may already exist; any real write failure surfaces below.
    }
  }
  Deno.writeTextFileSync(file, JSON.stringify(prefs, null, 2) + "\n");
}

// Get the recorded shipping-email preference, or null when it was never asked
// (absent file or absent key). null is the "unset" state the agent acts on.
export function getShippingEmailPref(file: string = orderPrefsFile()): ShippingEmailPref | null {
  return readOrderPrefs(file).shippingEmail ?? null;
}

// Record the shipping-email preference (opt in with an address, or opt out).
// Merges into any other prefs already in the file so unrelated keys survive.
export function setShippingEmailPref(
  pref: ShippingEmailPref,
  file: string = orderPrefsFile(),
): void {
  const prefs = readOrderPrefs(file);
  prefs.shippingEmail = pref;
  writeOrderPrefs(prefs, file);
}

// A plausible-email check: bounded length, exactly one @, a dotted domain, and
// no whitespace. Deliberately permissive, enough to reject fat-fingered junk
// ("notanemail", "a b@c", "a@b") without pretending to be a full RFC 5322
// validator. The address is buyer-provided and only ever placed on
// order_attributes.contact_email.
export function isPlausibleEmail(s: unknown): boolean {
  if (typeof s !== "string") return false;
  const v = s.trim();
  if (v.length < 3 || v.length > 254) return false;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return false;
  if (v.includes("..")) return false;
  const at = v.indexOf("@");
  const local = v.slice(0, at);
  const domain = v.slice(at + 1);
  if (local.length === 0 || local.length > 64) return false;
  if (domain.length === 0 || domain.length > 255) return false;
  return true;
}

// Decide the throwaway shipping email for one checkout, plus the signal the
// agent reads. A one-shot override (already validated by the caller) wins and
// does NOT change the stored default. Otherwise the stored preference decides:
// opted in with a usable address attaches it; opted in with no usable address
// falls back to "unset" so the agent re-asks; opted out attaches nothing and
// signals not to ask; a null (never asked) preference signals "unset".
export function resolveShippingEmail(
  override: string | null,
  pref: ShippingEmailPref | null,
): { email: string | null; signal: ShippingEmailSignal } {
  if (override !== null && override !== "") return { email: override, signal: "override" };
  if (pref === null) return { email: null, signal: "unset" };
  if (pref.optedIn) {
    if (typeof pref.address === "string" && pref.address !== "" && isPlausibleEmail(pref.address)) {
      return { email: pref.address, signal: "opted_in" };
    }
    return { email: null, signal: "unset" };
  }
  return { email: null, signal: "opted_out" };
}

// Attach the throwaway shipping email onto the order-attributes object that rides
// the UCP complete body, and return the agent-facing signal. Mutates in place:
// `buy` has already put gift_message / delivery_date / occasion on the object,
// so the email lands on the SAME order_attributes the pinned contract targets
// (the field name is exactly `contact_email`). This is the exact call `buy` makes, kept
// pure so it is verifiable offline with no wallet, secret, or network.
export function attachShippingEmail(
  orderAttributes: Record<string, string>,
  override: string | null,
  pref: ShippingEmailPref | null,
): ShippingEmailSignal {
  const { email, signal } = resolveShippingEmail(override, pref);
  if (email !== null) orderAttributes.contact_email = email;
  return signal;
}
