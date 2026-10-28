"""Build Prover.toml for circuits/no_ai_actions from a C2PA-signed JPEG.

Also writes the manifest-stripped JPEG that gets published alongside the
proof: its SHA-256 equals the signed c2pa.hash.data value, which is the
circuit's public `asset_hash`.

usage: make_witness.py SIGNED.jpg OUT_DIR
"""
import hashlib
import json
import os
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(__file__))
from jumbf import find, jumbf_from_jpeg, parse_boxes  # noqa: E402

# Must match the globals in circuits/no_ai_actions/src/main.nr
MAX_TBS = 2048
MAX_ACTIONS = 512
MAX_HASH_DATA = 256

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

ACTIONS_URL = b"self#jumbf=c2pa.assertions/c2pa.actions.v2"
HASH_DATA_URL = b"self#jumbf=c2pa.assertions/c2pa.hash.data"


def hashed_uri_bytes(url: bytes, digest: bytes) -> bytes:
    # {"url": tstr, "hash": bstr .size 32} exactly as c2pa-rs serialises it
    return cbor2.dumps({"url": url.decode(), "hash": digest})


def assertion_body(active, label: str) -> bytes:
    """Bytes the claim's hashed-uri covers: superbox minus its 8-byte header."""
    box = find([active], label)
    assert box is not None, f"assertion {label} not found"
    return jumbf[box.offset + 8:box.end]


def pad(b: bytes, n: int) -> list:
    assert len(b) <= n, f"{len(b)} bytes exceeds circuit max {n}"
    return list(b) + [0] * (n - len(b))


def toml_arr(xs) -> str:
    return "[" + ", ".join(str(x) for x in xs) + "]"


signed_path, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
data = open(signed_path, "rb").read()
jumbf = jumbf_from_jpeg(data)
root = parse_boxes(jumbf, 0, len(jumbf))
# the active manifest is the last in the store; every lookup below is scoped
# to it, so an ingredient's manifest earlier in the store can't be mixed in
active = root[0].children[-1]

# --- claim + COSE_Sign1 -> Sig_structure (the exact bytes ES256 signs) ---
claim = find([active], "c2pa.claim.v2").children[1].payload
protected, _unprotected, _payload, sig = cbor2.loads(
    find([active], "c2pa.signature").children[1].payload).value
tbs = cbor2.dumps(["Signature1", protected, b"", claim])
assert tbs[15:15 + len(protected)] == protected
assert tbs[19 + len(protected):] == claim

r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
if s > P256_N // 2:  # barretenberg only accepts low-s signatures
    s = P256_N - s
signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

leaf = x509.load_der_x509_certificate(cbor2.loads(protected)[33][0])
point = leaf.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
pub_x, pub_y = point[1:33], point[33:65]

# --- assertions referenced from the claim ---
actions = assertion_body(active, "c2pa.actions.v2")
hash_data = assertion_body(active, "c2pa.hash.data")
actions_ref = hashed_uri_bytes(ACTIONS_URL, hashlib.sha256(actions).digest())
hash_data_ref = hashed_uri_bytes(HASH_DATA_URL, hashlib.sha256(hash_data).digest())
claim_start = 19 + len(protected)
actions_ref_offset = tbs.index(actions_ref, claim_start)
hash_data_ref_offset = tbs.index(hash_data_ref, claim_start)

hd = cbor2.loads(find([active], "c2pa.hash.data").children[1].payload)
asset_hash = hd["hash"]
asset_hash_offset = hash_data.index(b"\x64hash\x58\x20" + asset_hash)

# --- the published image: manifest removed, so sha256(file) == asset_hash ---
ex = hd["exclusions"][0]
stripped = data[:ex["start"]] + data[ex["start"] + ex["length"]:]
assert hashlib.sha256(stripped).digest() == asset_hash
open(os.path.join(out_dir, "published.jpg"), "wb").write(stripped)

fields = {
    "signer_pubkey_x": toml_arr(pub_x),
    "signer_pubkey_y": toml_arr(pub_y),
    "asset_hash": toml_arr(asset_hash),
    "signature": toml_arr(signature),
    "tbs": toml_arr(pad(tbs, MAX_TBS)),
    "tbs_len": len(tbs),
    "protected_len": len(protected),
    "actions": toml_arr(pad(actions, MAX_ACTIONS)),
    "actions_len": len(actions),
    "actions_ref_offset": actions_ref_offset,
    "hash_data": toml_arr(pad(hash_data, MAX_HASH_DATA)),
    "hash_data_len": len(hash_data),
    "hash_data_ref_offset": hash_data_ref_offset,
    "asset_hash_offset": asset_hash_offset,
}
with open(os.path.join(out_dir, "Prover.toml"), "w") as f:
    for k, v in fields.items():
        f.write(f'{k} = {v if isinstance(v, str) else json.dumps(str(v))}\n')

# public values a verifier checks the proof against (no private metadata)
json.dump({"signer_pubkey": point.hex(), "asset_hash": asset_hash.hex()},
          open(os.path.join(out_dir, "public.json"), "w"), indent=2)
print(f"tbs={len(tbs)} actions={len(actions)} hash_data={len(hash_data)} -> {out_dir}")
