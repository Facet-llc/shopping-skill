# Facet Shopping Skill

An open, non-custodial [Agent Skill](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
that lets an AI assistant shop any Facet-enabled store and complete a real
purchase on the user's behalf, using the user's own agent identity and the
user's own self-custodied wallet. No middleman ever holds the money or the key.

[![CI](https://github.com/Facet-llc/shopping-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/Facet-llc/shopping-skill/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Custody: none](https://img.shields.io/badge/custody-none-brightgreen.svg)](SECURITY.md)

The assistant browses the merchant's normal, human-facing storefront, the same
pages a person sees. Only when it discovers the store is agent-ready does it
switch to the signed rail: it self-issues a wallet-bound identity, finds the
store's Facet Terminal, prices the cart, and settles on-chain in USDC after the
user confirms. Card numbers are never typed into a web form.

## Non-custodial by construction

This is the first thing to understand, because this skill signs a payment with
your wallet key.

- **Your private key never leaves your machine.** It is read from an environment
  variable, used to sign a payment authorization inside a local Deno process, and
  is never transmitted, logged, or written to disk. Only the resulting signature,
  an authorization to move a specific amount to a specific on-chain escrow, leaves
  the process.
- **Funds settle straight from your wallet into the merchant's on-chain escrow.**
  No Facet server, and no other third party, ever holds your money or your key.
- **The identity is yours too.** The skill self-issues a wallet-bound Facet KYA
  (an ES256 bearer token) from the public issuer by proving control of your
  wallet. There is no issuer service key anywhere in this repository.

### Verify it yourself

Do not take the claim on faith. The code is short and readable, and you can
confirm the key handling in a few greps:

```bash
# The wallet key is only ever read from the environment, never printed or sent.
grep -n "WALLET_KEY\|signMessage\|signTypedData\|console.log" scripts/*.ts

# No hardcoded secrets, tokens, or issuer keys ship in this repo.
grep -rniE "secret|api[_-]?key|private[_-]?key\s*=|BEGIN (RSA|EC|PRIVATE)" scripts/ SKILL.md
```

The full threat model, and every guardrail mapped to the attack it defends, is
in [`references/security-model.md`](references/security-model.md). Responsible
disclosure is in [`SECURITY.md`](SECURITY.md).

## What it does

"Shopping" is two jobs behind one word, and they use opposite tools:

1. **Discovery and selection** happen on the merchant's real storefront, in the
   assistant's own browser. The catalog is not rebuilt into a panel; the store's
   own pages render it better.
2. **Checkout and settlement** happen on Facet's signed, agent-native rail: a UCP
   checkout session, a KYA-bearer identity, a locally signed on-chain payment, and
   a signed receipt.

The full flow, the rails, and the discovery mechanics are in
[`references/architecture.md`](references/architecture.md).

## Scope

This skill guides an agent through Facet identity and checkout, and nothing more:
discovering the Terminal, the KYA handshake, quoting a cart, and settling on the
signed rail. It does not try to be a human-facing shopping experience.

That surface, the conversational UI, native web browsing, and product search, is
owned by the host assistant (Claude, ChatGPT, Gemini) that renders the storefront
and helps the user choose. This skill takes the cart the user approved and
completes the purchase.

We welcome contributions that build a richer human-facing selection layer (native
browsing, product search, comparison) that hands an approved cart to this skill for
checkout. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick start

Requirements: [Deno](https://deno.com) (the runtime). The two dependencies, a
wallet signer and the escrow client, are pulled on first run and locked in
`deno.lock`.

The skill is driven over MCP, and MCP is the only interface. Point your agent's
MCP client at the stdio server:

```bash
deno run --allow-env --allow-read --allow-run --allow-net \
  --allow-write="$HOME/.cache,$HOME/.facet" scripts/mcp-server.ts
```

Provide the wallet through the environment (never on a command line); the server
reads it and the key stays inside the process:

```bash
export FACET_WALLET_KEY=0x...        # your wallet private key (0x + 64 hex); signs locally
export FACET_KYA=...                 # optional; a wallet-bound KYA is self-issued if absent
```

The agent then works entirely through the `facet_*` tools the server exposes:
`facet_wallet_new` (mint a self-custodied wallet; the recovery phrase is shown once
on the child's stderr, never in a tool result), `facet_wallet_list`,
`facet_discover` (is a store agent-ready), `facet_buy` (dry by default; nothing
settles until a second call with `settle: true` and the exact confirmed price), and
the full post-purchase lifecycle. See [`SKILL.md`](SKILL.md) for the flow the agent
follows and the complete tool reference.

## A reference implementation, not the only path

Facet's rails are open and published: agents.txt discovery, the Facet KYA
(ES256), the [UCP](https://ucp.dev) checkout, x402 over HTTP-402, ERC-3009 on
USDC, and RFC 9421 request signing. An agent that can drive HTTP and sign with
its own wallet can transact on a Facet-enabled store using only those specs.

The scripts here are an auditable reference client and a fallback for agents that
cannot sign on their own. They are not a required intermediary. Nothing in this
repo is a closed rail.

## Repository layout

```
shopping-skill/
├── SKILL.md                       # the Agent Skill: the flow the assistant follows
├── scripts/
│   ├── facet-checkout.ts          # internal identity + money-path implementation the MCP tools spawn
│   ├── wallet.ts                  # mint a wallet (BIP-39), keychain/keystore storage, fund
│   ├── kya-provision.ts           # self-serve wallet-bound KYA minter (no service key)
│   ├── mcp-server.ts              # drive the whole skill over MCP (stdio JSON-RPC)
│   ├── order-prefs.ts             # throwaway shipping-email preference store
│   ├── browse-storefront.ts       # last-resort public-catalog reader (no secrets)
│   ├── facet-checkout.test.ts     # offline tests for the buyer-side validators
│   ├── wallet.test.ts             # offline tests for wallet mint and storage
│   └── mcp-server.test.ts         # offline tests for the MCP tool surface
├── references/
│   ├── security-model.md          # threat model + every guardrail
│   ├── safety.md                  # agent-behavior safety layer (injection, prohibited goods)
│   ├── architecture.md            # the flow, the rails, discovery, UCP checkout
│   ├── receipt-verification.md    # how a signed receipt is verified offline
│   ├── legal.md                   # terms, acceptable use, identity, data handling
│   └── troubleshooting.md         # error taxonomy
├── .github/                       # issue + PR templates and the CI workflow
├── SECURITY.md                    # responsible disclosure + non-custodial invariant
├── CONTRIBUTING.md                # dev setup, gates, PR expectations
├── CODE_OF_CONDUCT.md             # contributor conduct
├── CHANGELOG.md                   # SemVer history
├── THIRD_PARTY_NOTICES.md         # attribution for loaded dependencies
├── deno.json  /  deno.lock        # tasks + fmt/lint config, locked dependency graph
└── LICENSE                        # Apache-2.0
```

## Development

```bash
deno task check    # type-check the scripts
deno task lint     # lint
deno task test     # run the offline validator tests (no secrets, no network)
deno task fmt      # format
```

The offline test suite exercises the buyer-side offer validator against the
honest path and every tampering vector (inflated amount, swapped token, wrong
chain, substituted recipient) with no wallet, no secrets, and no network.

## Security

This skill moves real funds. Read [`SECURITY.md`](SECURITY.md) before use, and
report any vulnerability through the process described there rather than a public
issue. Terms, acceptable use, the identity credential, and data handling are in
[`references/legal.md`](references/legal.md).

## License

Apache-2.0. Copyright 2026 Facet, LLC. See [`LICENSE`](LICENSE) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
