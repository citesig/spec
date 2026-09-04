# CiteSig — JavaScript reference implementation

The JavaScript reference implementation lives on npm as [`@citesig/core`](https://www.npmjs.com/package/@citesig/core).

```bash
npm install @citesig/core
```

- **Package:** [`@citesig/core`](https://www.npmjs.com/package/@citesig/core)
- **Current version:** 0.1.0
- **Runtime:** Node.js 18 or later. Zero runtime dependencies (uses built-in `node:crypto` for Ed25519).
- **License:** MIT
- **Conformance:** passes all 8 vectors in [`test-vectors/v0.1/`](../../test-vectors/v0.1/)

## Public API

```javascript
import { sign, verify, canonicalize, toCompact, parseCompact } from '@citesig/core';
```

See the [package README](https://www.npmjs.com/package/@citesig/core) for usage examples and the full API surface, including `did:key:` helpers and Ed25519 primitives.

## Running the tests

The conformance test suite bundles a byte-identical copy of `test-vectors/v0.1/` from this repo and runs every vector on `node --test`. The test suite is not shipped in the published npm tarball; run it from a source checkout when validating a new port or a change to `@citesig/core`.

## Cross-implementation compatibility

Signatures produced by `@citesig/core` verify against the Python [`citesig`](../py/README.md) package byte-for-byte, and vice versa. Both packages canonicalize claims identically and use the same Ed25519 primitives.
