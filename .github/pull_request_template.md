## Summary

What does this change and why?

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactor or tooling

## Checklist

- [ ] `deno task check`, `deno task lint`, and `deno task test` pass locally
- [ ] The wallet key still stays local: not transmitted, logged, or persisted
- [ ] The non-custodial invariant is preserved (Facet holds no funds or keys)
- [ ] Money-path or identity changes include a test that encodes the attack
      (fails before this change, passes after)
- [ ] Docs updated (SKILL.md / README / references) if behavior changed
- [ ] No secrets, internal hosts, or private paths added

## Security-sensitive change

If this touches the guardrails, offer validation, the settle gate, or identity,
describe the threat considered and how it is handled. For a suspected
vulnerability, stop and follow [SECURITY.md](SECURITY.md) instead of this PR.
