# CiteSig

An open protocol for embedding cryptographic verification signatures inside factual claims — a trust layer for AI-generated and AI-consumed text.

**Status:** draft. v0.1 is a request-for-comment, not a stable interface. Everything in this repo is subject to change until v1.0.

## What CiteSig is

When a language model, agent, or human publishes a factual claim, CiteSig is a compact, standards-friendly way to attach four things to that claim:

1. **What was said** — the canonical text of the claim.
2. **Who said it** — the signing party's public identity.
3. **What backs it** — the source or sources the claim rests on.
4. **How to verify the above** — a signature over (1)+(2)+(3) that anyone can check with the signer's public key.

A CiteSig-signed claim is portable: it can travel through model context, be re-quoted, get pasted into another document, and still carry a machine-checkable trail back to the party who first attested it.

## What CiteSig is not

- Not a truth oracle. A valid signature means "this signer stands behind this claim with these sources at this time." It does not mean the claim is correct.
- Not a citation format. Existing citation styles (APA, MLA, BibTeX, JATS, schema.org `Citation`) already handle "which source." CiteSig sits **around** a claim + its sources, not inside the source list.
- Not a proof-of-work chain. There is no CiteSig blockchain, no CiteSig token, no CiteSig network. Verification is offline and pairwise.

## Reference implementations

Both reference libraries are published, share the same test vectors, and produce byte-identical signatures across languages.

| Language | Package | Install |
|---|---|---|
| JavaScript / Node | [`@citesig/core`](https://www.npmjs.com/package/@citesig/core) | `npm install @citesig/core` |
| Python | [`citesig`](https://pypi.org/project/citesig/) | `pip install citesig` |

The [CiteSig verifier browser extension](https://github.com/citesig/verifier-extension) ships a browser-friendly port of `@citesig/core` and verifies attestations offline with WebCrypto.

## Repository layout

```
spec/
  v0.1.md             The current draft specification
test-vectors/
  v0.1/
    canonical.json    Canonical JSON serialization examples
    signatures.json   Known-good signature examples with keys
```

## Contributing

Issues and pull requests are welcome. Please open an issue before submitting substantive PRs so we can align on scope.

## License

Specification text: [Creative Commons Attribution 4.0 (CC-BY-4.0)](LICENSE-SPEC).
Code and test vectors: [MIT](LICENSE-CODE).

Dual licensing is intentional — the spec is meant to be quoted, translated, and re-hosted freely, while implementations should have permissive but attributable code terms.

## Related

- Draft context: [citesig.org](https://citesig.org)
- Sponsor: [DeepInquiry](https://deepinquiry.ai) — a commercial verified-facts API. DeepInquiry authors this draft but does not own the protocol. Once v1.0 is cut, governance transitions to a working group of implementers.
