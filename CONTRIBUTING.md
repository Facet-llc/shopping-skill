# Contributing

Thanks for your interest in improving the Facet Shopping Skill. This is a
buyer-side reference client for shopping a Facet-enabled store non-custodially.
Contributions that keep it small, auditable, and safe are very welcome.

## Where we would love help

This skill deliberately owns only the checkout rail. The human-facing shopping
experience is owned by the host assistant (Claude, ChatGPT, Gemini). Contributions
that strengthen the selection layer are especially welcome, as long as the purchase
still runs through the Facet rail with explicit human approval:

- Native web browsing and richer storefront rendering for human selection.
- Product search and discovery across Facet-enabled merchants.
- A clearer cart-review and comparison surface before purchase.

The rule for any such contribution: the human approves the cart, then settlement
runs through Facet checkout non-custodially. Selection is the host's surface;
settlement is Facet's rail.

## Ground rules

- **The non-custodial invariant is not negotiable.** Any change that would
  transmit, log, or persist the wallet key, or that would make Facet (or any third
  party) a custodian of funds or keys, will be rejected. The key is read from the
  environment, signs locally, and only signatures leave the process.
- **Keep it small.** This client is deliberately short and readable so a user can
  audit it before running it against their wallet. Prefer the boring, obvious
  change. New dependencies need a strong justification.
- **Money-path changes need a test that encodes the attack.** Any change to the
  guardrails, the offer validation, the settle gate, or the identity path must come
  with a test in `scripts/facet-checkout.test.ts` that fails before the change and
  passes after it.

## Development setup

You need [Deno](https://deno.com). Then:

```bash
git clone https://github.com/Facet-llc/shopping-skill.git
cd shopping-skill

deno task check    # type-check
deno task lint     # lint
deno task test     # offline validator tests (no secrets, no network)
deno task fmt      # format
```

All four must pass before you open a pull request. CI runs the same checks.

## Pull requests

- Describe what changed and why. Link the issue if there is one.
- Include tests for any behavior change, and the attack-encoding test for any
  money-path change.
- Keep the diff focused. Unrelated cleanups belong in their own PR.
- Contributions are accepted under the project's Apache-2.0 license (inbound equals
  outbound). There is no separate contributor license agreement.

Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`, `test:`) are
appreciated and make the changelog easier to keep.

## Reporting a security issue

Do not open a public issue or pull request for a suspected vulnerability. Follow
the private disclosure process in [`SECURITY.md`](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it.
