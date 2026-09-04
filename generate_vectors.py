"""Generate CiteSig v0.1 test vectors.

Produces two JSON files under test-vectors/v0.1/:

  canonical.json   - JCS canonicalization examples (input JSON -> canonical bytes)
  signatures.json  - Full attestations with known-good Ed25519 signatures,
                     tampered variants that MUST fail, and one deliberately-
                     malformed structural case.

The private key used is fixed and public — this repo distributes test
vectors, not secrets. Never reuse this key for real signing.
"""
import base64
import hashlib
import json
from pathlib import Path

import nacl.signing


# Public test key. This seed is published in this repo; do not reuse
# for anything real.
TEST_SEED_HEX = "8a5f2d5e6c1b9d4f0a3e2b7c9d8e1f0a5b6c7d8e9f0a1b2c3d4e5f6071829344"

signing_key = nacl.signing.SigningKey(bytes.fromhex(TEST_SEED_HEX))
verify_key = signing_key.verify_key
verify_key_bytes = bytes(verify_key)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# Build a did:key identifier from the raw Ed25519 public key.
# did:key format: "did:key:z" + multibase(base58btc, 0xed01 || raw_pubkey)
# 0xed01 is the multicodec prefix for Ed25519 public keys.
def did_key_ed25519(pubkey: bytes) -> str:
    import base58  # type: ignore
    prefixed = b"\xed\x01" + pubkey
    return "did:key:z" + base58.b58encode(prefixed).decode("ascii")


try:
    SIGNER_DID = did_key_ed25519(verify_key_bytes)
except ImportError:
    # Fallback: an https signer URL, still valid per spec §5.1.
    SIGNER_DID = "https://example.test/.well-known/citesig.json"


def jcs(obj) -> bytes:
    """RFC 8785 JCS canonicalization.

    This is a small correct-for-our-inputs implementation. It is not a
    general JCS library — it handles the field types CiteSig attestations
    use (strings, integers, floats round-trippable to shortest form,
    booleans, null, arrays, and objects). Implementers of production
    verifiers should use a full JCS library."""
    return json.dumps(
        obj,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_attestation(att: dict) -> dict:
    """Return a copy of `att` with the sig field populated."""
    unsigned = {k: v for k, v in att.items() if k != "sig"}
    signing_input = jcs(unsigned)
    sig = signing_key.sign(signing_input).signature
    return {**unsigned, "sig": b64url(sig)}


def source_digest(sources: list) -> str:
    """SHA-256 hex digest of the JCS canonicalization of the sources array,
    for the compact form (§6)."""
    return hashlib.sha256(jcs(sources)).hexdigest()


# ---------------------------------------------------------------------------
# canonical.json — JCS canonicalization examples

canonical_examples = [
    {
        "name": "key-order-invariance",
        "note": "Object key order does not affect canonical output.",
        "input": {"b": 2, "a": 1, "c": 3},
        "canonical_bytes_utf8": jcs({"a": 1, "b": 2, "c": 3}).decode("utf-8"),
    },
    {
        "name": "insignificant-whitespace-stripped",
        "note": "Whitespace outside string values does not appear in canonical output.",
        "input_pretty": "{\n  \"a\": 1,\n  \"b\": 2\n}",
        "canonical_bytes_utf8": '{"a":1,"b":2}',
    },
    {
        "name": "utf8-preserved",
        "note": "Non-ASCII characters are preserved as UTF-8, not escaped.",
        "input": {"claim": "The Louvre is in Paris — the largest art museum on Earth."},
        "canonical_bytes_utf8": '{"claim":"The Louvre is in Paris — the largest art museum on Earth."}',
    },
    {
        "name": "empty-sources-array",
        "note": "Empty arrays canonicalize to two bytes.",
        "input": {"sources": []},
        "canonical_bytes_utf8": '{"sources":[]}',
    },
]


# ---------------------------------------------------------------------------
# signatures.json — end-to-end signing / verification vectors

vector_1_input = {
    "v": "citesig/0.1",
    "claim": "The Great Barrier Reef is approximately 2,300 km long.",
    "signer": SIGNER_DID,
    "sources": [
        {"url": "https://en.wikipedia.org/wiki/Great_Barrier_Reef"},
        {"url": "doi:10.1029/2020JG005914"},
    ],
    "issued_at": "2026-09-03T20:41:00Z",
}
vector_1_signed = sign_attestation(vector_1_input)

# A tampered variant: same signature, altered claim. MUST fail verification.
vector_1_tampered = {
    **vector_1_signed,
    "claim": "The Great Barrier Reef is approximately 23,000 km long.",
}

# Empty sources — valid but weak.
vector_2_input = {
    "v": "citesig/0.1",
    "claim": "Water boils at 100 degrees Celsius at sea level.",
    "signer": SIGNER_DID,
    "sources": [],
    "issued_at": "2026-09-03T20:41:00Z",
}
vector_2_signed = sign_attestation(vector_2_input)

# Structurally malformed: wrong version literal. MUST be rejected before
# signature check.
vector_3_malformed = {
    **vector_1_signed,
    "v": "citesig/0.2",
}

# Extension field: signed, valid, present in verified output.
vector_4_input = {
    "v": "citesig/0.1",
    "claim": "Mount Everest's summit is 8,848.86 meters above sea level (Nepal/China 2020 remeasurement).",
    "signer": SIGNER_DID,
    "sources": [
        {
            "url": "https://kathmandupost.com/national/2020/12/08/mt-everest-is-8-848-86m-tall-china-nepal-make-joint-announcement",
        },
    ],
    "issued_at": "2026-09-03T20:41:00Z",
    "deepinquiry:tier": "gold",
}
vector_4_signed = sign_attestation(vector_4_input)

# Same as vector_4 but the extension field was removed after signing.
# Verifier MUST reject because the signed content changed.
vector_4_ext_stripped = {k: v for k, v in vector_4_signed.items() if k != "deepinquiry:tier"}

# Compact form of vector_1.
compact = ":".join([
    "citesig",
    "0.1",
    b64url(vector_1_signed["claim"].encode("utf-8")),
    b64url(vector_1_signed["signer"].encode("utf-8")),
    b64url(bytes.fromhex(source_digest(vector_1_signed["sources"]))),
    b64url(vector_1_signed["issued_at"].encode("utf-8")),
    vector_1_signed["sig"],
])

signature_vectors = {
    "test_key": {
        "note": (
            "The private seed used for these vectors is published in this repo "
            "and MUST NOT be reused for real signing. Verifiers can reproduce every "
            "expected signature from `seed_hex`."
        ),
        "seed_hex": TEST_SEED_HEX,
        "public_key_base64url": b64url(verify_key_bytes),
        "signer": SIGNER_DID,
    },
    "vectors": [
        {
            "id": "v0.1-signed-01",
            "description": "Two sources, non-empty, must verify.",
            "attestation": vector_1_signed,
            "expected": "ACCEPT",
        },
        {
            "id": "v0.1-signed-02",
            "description": "Empty sources array — valid but weak, must verify.",
            "attestation": vector_2_signed,
            "expected": "ACCEPT",
        },
        {
            "id": "v0.1-signed-03",
            "description": "Signed extension field, must verify and be preserved.",
            "attestation": vector_4_signed,
            "expected": "ACCEPT",
        },
        {
            "id": "v0.1-reject-01",
            "description": "Claim tampered after signing — signature MUST fail.",
            "attestation": vector_1_tampered,
            "expected": "REJECT",
            "reason": "signature-invalid",
        },
        {
            "id": "v0.1-reject-02",
            "description": "Unknown protocol version — verifier MUST reject before signature check.",
            "attestation": vector_3_malformed,
            "expected": "REJECT",
            "reason": "version-unknown",
        },
        {
            "id": "v0.1-reject-03",
            "description": "Extension field stripped after signing — signature MUST fail.",
            "attestation": vector_4_ext_stripped,
            "expected": "REJECT",
            "reason": "signature-invalid",
        },
    ],
    "compact_form": {
        "id": "v0.1-compact-01",
        "description": "Compact form derived from v0.1-signed-01.",
        "source_attestation_id": "v0.1-signed-01",
        "compact": compact,
    },
}


# ---------------------------------------------------------------------------
# Write outputs

out = Path("test-vectors/v0.1")
out.mkdir(parents=True, exist_ok=True)

(out / "canonical.json").write_text(json.dumps(canonical_examples, indent=2) + "\n")
(out / "signatures.json").write_text(json.dumps(signature_vectors, indent=2) + "\n")

# Sanity: verify each ACCEPT vector round-trips through nacl.
for v in signature_vectors["vectors"]:
    att = v["attestation"]
    unsigned = {k: val for k, val in att.items() if k != "sig"}
    signing_input = jcs(unsigned)
    sig_bytes = base64.urlsafe_b64decode(att["sig"] + "==")
    try:
        verify_key.verify(signing_input, sig_bytes)
        ok = True
    except Exception:
        ok = False
    assert ok == (v["expected"] == "ACCEPT" and v["attestation"].get("v") == "citesig/0.1"), (
        f"vector {v['id']}: signature-verify result did not match expected"
    )

print("wrote", out / "canonical.json")
print("wrote", out / "signatures.json")
