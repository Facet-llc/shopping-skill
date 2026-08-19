# Third-party notices

The Facet Shopping Skill does not vendor any third-party source. At runtime the
Deno scripts load the following components through pinned `npm:` and `jsr:`
specifiers (exact versions are locked in `deno.lock`). Their licenses and
copyright notices are reproduced or referenced below.

| Component | Version | License | Source |
|---|---|---|---|
| `viem` | 2.50.4 | MIT | https://github.com/wevm/viem |
| `jose` | 5.9.6 | MIT | https://github.com/panva/jose |
| `@bosonprotocol/x402-client` | 0.3.1 | Apache-2.0 | https://github.com/bosonprotocol/x402B |
| `@std/assert` (tests only) | ^1 | MIT | https://github.com/denoland/std |

## MIT components

The following components are licensed under the MIT License, under their
respective copyright notices:

- `viem`: Copyright (c) the viem authors. See the linked repository for the
  authoritative copyright notice.
- `jose`: Copyright (c) 2018 Filip Skokan.
- `@std/assert`: Copyright the Deno authors (Deno Standard Library).

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Apache-2.0 components

`@bosonprotocol/x402-client` is licensed under the Apache License, Version 2.0
(Copyright 2026 Boson Protocol), the same license this project ships under; see
[`LICENSE`](LICENSE) for the full text. The upstream distribution carries a
`NOTICE` file; consult the linked repository for its current attribution
notices.
