# CiteSig — Python reference implementation

The Python reference implementation lives on PyPI as [`citesig`](https://pypi.org/project/citesig/).

```bash
pip install citesig
```

- **Package:** [`citesig`](https://pypi.org/project/citesig/)
- **Current version:** 0.1.0
- **Runtime:** Python 3.9 through 3.13.
- **Dependencies:** `cryptography>=41.0.0` for Ed25519 primitives.
- **License:** MIT
- **Conformance:** passes all 8 vectors in [`test-vectors/v0.1/`](../../test-vectors/v0.1/)

## Public API

```python
from citesig import sign, verify, canonicalize, to_compact, parse_compact
```

See the [package README](https://pypi.org/project/citesig/) for usage examples and the full API surface, including `did:key:` helpers and Ed25519 primitives.

## Running the tests

The conformance test suite bundles a byte-identical copy of `test-vectors/v0.1/` from this repo and runs every vector on `pytest`. The test suite is not shipped in the published PyPI package; run it from a source checkout when validating a new port or a change to `citesig`.

## Cross-implementation compatibility

Signatures produced by `citesig` verify against the JavaScript [`@citesig/core`](../js/README.md) package byte-for-byte, and vice versa. Both packages canonicalize claims identically and use the same Ed25519 primitives.
