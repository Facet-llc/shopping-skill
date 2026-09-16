# Install on Meta Muse Code

This skill runs natively on [Meta Muse Code](https://developer.meta.com/ai/products/muse-code/)
(1.3.0 and later). Muse has no separate plugin format: a "plugin" is a
registered **skill** plus a registered **MCP server**, which is exactly what this
repo already is. Registering both makes Muse load `SKILL.md` and expose the
`facet_*` tools.

Requirements: [Deno](https://deno.com) and the `muse` CLI on your PATH.

## One command

From the repository root:

```bash
deno run --allow-env --allow-read --allow-write --allow-run muse/install.ts
```

That does two things and writes no secret anywhere:

1. `muse skills install <repo> --scope user --force` so Muse loads the skill.
2. Adds a `facet-shopping` entry under `mcpServers` in
   `~/.config/muse/settings.json` (creating the file with `schema_version: 1` if
   absent, preserving anything already there).

Then export your wallet key in the shell that starts `muse` and run it:

```bash
export FACET_WALLET_KEY=0x...        # your wallet private key (0x + 64 hex); signs locally
export FACET_KYA=...                 # optional; a wallet-bound KYA is self-issued if absent
muse
```

Ask Muse to "go shopping at" a Facet-enabled store. It loads the skill and calls
the `facet_*` tools over MCP.

## Manual setup

If you would rather wire it by hand, do the same two steps yourself.

**1. Register the skill.** Either let Muse discover it (Muse reads
`~/.claude/skills`, `~/.agents/skills`, and `$XDG_CONFIG_HOME/muse/skills`), or
install this repo as a user skill from the repository root:

```bash
muse skills install "$(pwd)" --scope user --force
muse skills validate "$(pwd)"      # prints: valid  shopping
```

**2. Register the MCP server.** Add this block to
`~/.config/muse/settings.json`, merging it with anything already there. The
top-level `schema_version` is required by Muse. Point `args` at this repo's
launcher with an absolute path (see [`settings.example.json`](settings.example.json)):

```json
{
  "schema_version": 1,
  "mcpServers": {
    "facet-shopping": {
      "command": "bash",
      "args": ["/absolute/path/to/shopping-skill/muse/facet-shopping.sh"]
    }
  }
}
```

The launcher [`facet-shopping.sh`](facet-shopping.sh) runs the same stdio MCP
server the top-level README documents, with the same Deno permissions. It reads
`FACET_WALLET_KEY` from the environment; the key never appears in this repo or in
`settings.json`.

## Keeping the wallet key out of settings.json

`settings.json` holds only the launch command, never a key. Export
`FACET_WALLET_KEY` in the shell that starts `muse`, exactly as with any other
host. This is the same non-custodial contract described in the
[top-level README](../README.md) and [security model](../references/security-model.md):
the key is read from the environment inside a local Deno process, used to sign,
and never transmitted, logged, or written to disk.

## Updating

The MCP server runs from your clone, so update it with `git pull`. Re-run the
installer (or `muse skills install "$(pwd)" --scope user --force`) to refresh the
skill text Muse copied into its store.

## Uninstalling

```bash
muse skills uninstall shopping
```

Then remove the `facet-shopping` entry from `mcpServers` in
`~/.config/muse/settings.json`.

## Troubleshooting

- **The `facet_*` tools do not appear.** Confirm the entry parsed:
  `muse mcp logout facet-shopping` should report that `facet-shopping` is a stdio
  server (not "no MCP server named ... is configured"). If it reports the config
  is faulted, fix the JSON in `settings.json`, most often a missing top-level
  `schema_version`.
- **A tool fails to reach the network or write a receipt.** The server needs
  outbound HTTPS (to the store's Facet Terminal and the Base RPC) and write
  access to `~/.cache` and `~/.facet`. If Muse's sandbox blocks it, allow those
  for the workspace; see the safety flags in `muse --help`.
- **`deno: command not found`.** Install Deno from https://deno.com and reopen
  the shell.
