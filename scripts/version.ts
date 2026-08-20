// The skill's released version and the public GA repository it is published from.
//
// SKILL_VERSION is the single source of truth for "what version am I". Bump it with
// each release so it matches the git tag and the newest DATED section of CHANGELOG.md;
// version.test.ts asserts that CHANGELOG match, so a release cannot forget to bump it.
// The `version` subcommand reads the newest tag from the GA repo's public GitHub API
// and compares it against this, so a user can confirm they are on the latest GA release.

export const SKILL_VERSION = "1.3.0";

/** The public GA repository, `owner/repo`. Releases are published here as git tags. */
export const SKILL_REPO = "Facet-llc/shopping-skill";

/** The GA repo's public tags endpoint. Unauthenticated (a public repo), so it is
 *  rate-limited per IP; the `version` check is occasional, well within that. */
export const SKILL_TAGS_URL = `https://api.github.com/repos/${SKILL_REPO}/tags?per_page=100`;

/** Parse a semver `X.Y.Z` (a leading `v` is tolerated, any suffix ignored) into
 *  `[major, minor, patch]`, or null when it does not look like a version. */
export function parseSemver(v: string): [number, number, number] | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(v.trim());
  if (m === null) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** Compare two semver strings. Negative if a is older than b, 0 if equal, positive if
 *  a is newer. An unparseable version is treated as the oldest, so a garbled remote
 *  never reads as "newer" and never prompts a spurious update. */
export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (pa === null && pb === null) return 0;
  if (pa === null) return -1;
  if (pb === null) return 1;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

/** Given the GitHub tags API payload (an array of `{ name }`), return the highest
 *  semver tag as a normalized `X.Y.Z` (no leading `v`), or null when none parse.
 *  The tags endpoint does not guarantee semver order, so this picks the max itself.
 *  Pure, so it is unit-tested offline. */
export function latestTag(tags: unknown): string | null {
  if (!Array.isArray(tags)) return null;
  let best: string | null = null;
  for (const t of tags) {
    const name = (t as { name?: unknown } | null)?.name;
    if (typeof name !== "string") continue;
    const p = parseSemver(name);
    if (p === null) continue;
    const norm = `${p[0]}.${p[1]}.${p[2]}`;
    if (best === null || compareSemver(norm, best) > 0) best = norm;
  }
  return best;
}

/** The shape the `version` command reports, and the pure decision behind it. Given the
 *  local version and the latest GA tag (or null when GitHub could not be reached), it
 *  returns whether the local build is current and, when a newer one exists, its release
 *  URL. Kept pure and separate from the fetch so it is unit-tested offline. */
export function versionReport(
  local: string,
  latest: string | null,
): {
  version: string;
  latest: string | null;
  up_to_date: boolean | null;
  repo: string;
  update_url?: string;
  message: string;
} {
  if (latest === null) {
    return {
      version: local,
      latest: null,
      up_to_date: null,
      repo: SKILL_REPO,
      message: `You are on ${local}. The latest GA version could not be determined (GitHub was unreachable).`,
    };
  }
  const current = compareSemver(local, latest) >= 0;
  return {
    version: local,
    latest,
    up_to_date: current,
    repo: SKILL_REPO,
    ...(current ? {} : { update_url: `https://github.com/${SKILL_REPO}/releases/tag/v${latest}` }),
    message: current
      ? `You are on the latest GA version (${local}).`
      : `A newer GA version ${latest} is available (you are on ${local}). Update: https://github.com/${SKILL_REPO}/releases/tag/v${latest}`,
  };
}
