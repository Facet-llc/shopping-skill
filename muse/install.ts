#!/usr/bin/env -S deno run --allow-env --allow-read --allow-write --allow-run
//
// One-command install of the Facet shopping skill into Meta Muse Code.
//
// It does the two things a native Muse plugin needs, and nothing else:
//   1. Registers the skill so Muse can load SKILL.md
//      (muse skills install <repo> --scope user).
//   2. Registers the facet-shopping MCP server so the facet_* tools exist,
//      by adding one entry under "mcpServers" in ~/.config/muse/settings.json.
//
// It never writes a wallet key anywhere. The key is read from the environment
// at runtime by the launcher (muse/facet-shopping.sh); see the README.
//
// Run:
//   deno run --allow-env --allow-read --allow-write --allow-run muse/install.ts
//
// Safe to run more than once: the settings merge preserves every other key and
// only sets the single facet-shopping entry.

const SERVER_NAME = "facet-shopping";

function repoRoot(): string {
  // muse/install.ts -> repo root is one directory up.
  const here = new URL(".", import.meta.url).pathname;
  return new URL("..", `file://${here}`).pathname.replace(/\/$/, "");
}

function configDir(): string {
  const xdg = Deno.env.get("XDG_CONFIG_HOME");
  const home = Deno.env.get("HOME");
  if (!xdg && !home) {
    throw new Error("neither XDG_CONFIG_HOME nor HOME is set; cannot locate Muse config");
  }
  const base = xdg && xdg.length > 0 ? xdg : `${home}/.config`;
  return `${base}/muse`;
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

async function haveCommand(cmd: string): Promise<boolean> {
  try {
    const p = new Deno.Command(cmd, { args: ["--version"], stdout: "null", stderr: "null" });
    const { success } = await p.output();
    return success;
  } catch {
    return false;
  }
}

async function registerSkill(root: string): Promise<void> {
  if (!(await haveCommand("muse"))) {
    console.log(
      "! muse is not on PATH; skipping the skill registration step.\n" +
        "  Install Muse Code, then run:\n" +
        `    muse skills install "${root}" --scope user --force`,
    );
    return;
  }
  console.log("> muse skills install (scope: user)");
  const p = new Deno.Command("muse", {
    args: ["skills", "install", root, "--scope", "user", "--force"],
    stdout: "inherit",
    stderr: "inherit",
  });
  const { success } = await p.output();
  if (!success) {
    throw new Error("muse skills install failed; see the output above");
  }
}

async function registerMcpServer(root: string): Promise<string> {
  const dir = configDir();
  const settingsPath = `${dir}/settings.json`;
  const launcher = `${root}/muse/facet-shopping.sh`;

  await Deno.mkdir(dir, { recursive: true });

  // deno-lint-ignore no-explicit-any
  let settings: Record<string, any> = { schema_version: 1 };
  if (await exists(settingsPath)) {
    const raw = (await Deno.readTextFile(settingsPath)).trim();
    if (raw.length > 0) {
      try {
        settings = JSON.parse(raw);
      } catch (e) {
        throw new Error(
          `refusing to overwrite a settings file that does not parse as JSON: ${settingsPath}\n` +
            `  fix or remove it, then re-run. (${(e as Error).message})`,
        );
      }
    }
  }

  if (typeof settings.schema_version !== "number") {
    settings.schema_version = 1;
  }
  if (typeof settings.mcpServers !== "object" || settings.mcpServers === null) {
    settings.mcpServers = {};
  }
  settings.mcpServers[SERVER_NAME] = {
    command: "bash",
    args: [launcher],
  };

  await Deno.writeTextFile(settingsPath, JSON.stringify(settings, null, 2) + "\n");
  return settingsPath;
}

async function main(): Promise<void> {
  const root = repoRoot();

  if (!(await haveCommand("deno"))) {
    console.error("deno is required but not on PATH. Install it from https://deno.com");
    Deno.exit(127);
  }

  // Make sure the launcher is executable even if the checkout dropped the bit.
  try {
    await Deno.chmod(`${root}/muse/facet-shopping.sh`, 0o755);
  } catch {
    // Non-fatal: on filesystems without POSIX modes, bash <launcher> still works.
  }

  await registerSkill(root);
  const settingsPath = await registerMcpServer(root);

  console.log("\nDone. The Facet shopping skill is registered with Muse Code.");
  console.log(`  skill:   loaded from this repo (or ~/.claude/skills if present)`);
  console.log(`  server:  facet-shopping added under mcpServers in ${settingsPath}`);
  console.log("\nNext:");
  console.log("  1. Export your wallet key in the shell that launches muse:");
  console.log("       export FACET_WALLET_KEY=0x...        # signs locally, never stored");
  console.log("       export FACET_KYA=...                 # optional; self-issued if absent");
  console.log('  2. Start muse and try: "go shopping at <a Facet-enabled store>".');
  console.log("     Muse loads the skill and the facet_* tools from the MCP server.");
}

if (import.meta.main) {
  await main();
}
