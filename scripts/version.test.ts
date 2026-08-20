import { assert, assertEquals } from "jsr:@std/assert@^1";
import { compareSemver, latestTag, parseSemver, SKILL_VERSION, versionReport } from "./version.ts";

Deno.test("parseSemver parses X.Y.Z with an optional leading v and ignores a suffix", () => {
  assertEquals(parseSemver("1.2.3"), [1, 2, 3]);
  assertEquals(parseSemver("v1.2.3"), [1, 2, 3]);
  assertEquals(parseSemver("v10.0.42-rc1"), [10, 0, 42]);
  assertEquals(parseSemver("nope"), null);
  assertEquals(parseSemver("1.2"), null);
});

Deno.test("compareSemver orders versions and sinks an unparseable one", () => {
  assert(compareSemver("1.2.0", "1.3.0") < 0);
  assert(compareSemver("1.3.0", "1.2.0") > 0);
  assertEquals(compareSemver("1.2.0", "v1.2.0"), 0);
  assert(compareSemver("1.2.0", "1.2.1") < 0);
  assert(compareSemver("2.0.0", "1.9.9") > 0);
  // An unparseable version is treated as the oldest, so a garbled remote never reads
  // as newer and never prompts a spurious update.
  assert(compareSemver("garbage", "1.0.0") < 0);
  assert(compareSemver("1.0.0", "garbage") > 0);
});

Deno.test("latestTag picks the highest semver tag regardless of order or noise", () => {
  assertEquals(latestTag([{ name: "v1.1.0" }, { name: "v1.2.0" }, { name: "v1.0.0" }]), "1.2.0");
  // Numeric ordering, not lexical (1.10.0 > 1.2.0), with a non-version tag mixed in.
  assertEquals(latestTag([{ name: "v1.2.0" }, { name: "latest" }, { name: "v1.10.0" }]), "1.10.0");
  assertEquals(latestTag([]), null);
  assertEquals(latestTag([{ name: "nightly" }]), null);
  assertEquals(latestTag("not-an-array"), null);
});

Deno.test("versionReport: up to date when local is at or ahead of latest", () => {
  const r = versionReport("1.2.0", "1.2.0");
  assertEquals(r.up_to_date, true);
  assertEquals(r.latest, "1.2.0");
  assert(r.update_url === undefined);
  assert(r.message.includes("latest"));
});

Deno.test("versionReport: newer available when local is behind latest", () => {
  const r = versionReport("1.2.0", "1.3.0");
  assertEquals(r.up_to_date, false);
  assertEquals(r.update_url, "https://github.com/Facet-llc/shopping-skill/releases/tag/v1.3.0");
  assert(r.message.includes("1.3.0"));
});

Deno.test("versionReport: unknown when GitHub was unreachable (latest null)", () => {
  const r = versionReport("1.2.0", null);
  assertEquals(r.up_to_date, null);
  assertEquals(r.latest, null);
  assert(r.update_url === undefined);
  assert(r.message.includes("could not be determined"));
});

// Guardrail: SKILL_VERSION must match the newest DATED section of CHANGELOG.md, so a
// release cannot bump the git tag / changelog without bumping the version, or vice versa.
Deno.test("SKILL_VERSION matches the newest dated CHANGELOG version", async () => {
  const changelog = await Deno.readTextFile(new URL("../CHANGELOG.md", import.meta.url));
  const m = /^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}/m.exec(changelog);
  assert(m !== null, "no dated version section found in CHANGELOG.md");
  assertEquals(SKILL_VERSION, m[1], `SKILL_VERSION ${SKILL_VERSION} does not match newest CHANGELOG ${m?.[1]}`);
});
