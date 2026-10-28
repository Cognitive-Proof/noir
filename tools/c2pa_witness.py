"""Witness extraction shared by the Noir-C2PA circuits.

extract() pulls everything the circuits need out of a C2PA-signed JPEG;
prover_toml() renders the subset a given circuit takes as Prover.toml.
"""
import hashlib
import os
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sys.path.insert(0, os.path.dirname(__file__))
from jumbf import find, jumbf_from_jpeg, parse_boxes  # noqa: E402

# Must match the globals in the circuits' main.nr
MAX_TBS = 2048
MAX_ACTIONS = 512
MAX_HASH_DATA = 256
MAX_TBS_CERT = 1024

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# SubjectPublicKeyInfo header for an uncompressed P-256 key
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04"

ACTIONS_URL = b"self#jumbf=c2pa.assertions/c2pa.actions.v2"
HASH_DATA_URL = b"self#jumbf=c2pa.assertions/c2pa.hash.data"


class NoManifest(Exception):
    pass


def hashed_uri_bytes(url: bytes, digest: bytes) -> bytes:
    # {"url": tstr, "hash": bstr .size 32} exactly as c2pa-rs serialises it
    return cbor2.dumps({"url": url.decode(), "hash": digest})


def low_s(r: int, s: int) -> bytes:
    """Raw r||s with s normalised to the low half (barretenberg rejects high-s)."""
    if s > P256_N // 2:
        s = P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def pubkey_point(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def extract(signed_path: str) -> dict:
    data = open(signed_path, "rb").read()
    try:
        jumbf = jumbf_from_jpeg(data)
    except AssertionError as e:
        raise NoManifest(str(e)) from e
    root = parse_boxes(jumbf, 0, len(jumbf))
    # the active manifest is the last in the store; every lookup below is
    # scoped to it, so an ingredient's manifest earlier in the store can't be
    # mixed in
    active = [root[0].children[-1]]

    def assertion_body(label):
        """Bytes the claim's hashed-uri covers: superbox minus its 8-byte header."""
        box = find(active, label)
        assert box is not None, f"assertion {label} not found"
        return jumbf[box.offset + 8:box.end]

    # --- claim + COSE_Sign1 -> Sig_structure (the exact bytes ES256 signs) ---
    claim = find(active, "c2pa.claim.v2").children[1].payload
    protected, _unprotected, _payload, sig = cbor2.loads(
        find(active, "c2pa.signature").children[1].payload).value
    tbs = cbor2.dumps(["Signature1", protected, b"", claim])
    assert tbs[15:15 + len(protected)] == protected
    assert tbs[19 + len(protected):] == claim
    signature = low_s(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))

    # --- leaf certificate (first in x5chain) ---
    leaf = x509.load_der_x509_certificate(cbor2.loads(protected)[33][0])
    point = pubkey_point(leaf.public_key())
    leaf_tbs_cert = leaf.tbs_certificate_bytes
    leaf_cert_sig = low_s(*decode_dss_signature(leaf.signature))
    leaf_spki_offset = leaf_tbs_cert.index(P256_SPKI_PREFIX)
    assert leaf_tbs_cert[leaf_spki_offset + 26:leaf_spki_offset + 91] == point

    # --- assertions referenced from the claim ---
    actions = assertion_body("c2pa.actions.v2")
    hash_data = assertion_body("c2pa.hash.data")
    actions_ref = hashed_uri_bytes(ACTIONS_URL, hashlib.sha256(actions).digest())
    hash_data_ref = hashed_uri_bytes(HASH_DATA_URL, hashlib.sha256(hash_data).digest())
    claim_start = 19 + len(protected)

    hd = cbor2.loads(find(active, "c2pa.hash.data").children[1].payload)
    asset_hash = hd["hash"]

    # --- the published image: manifest removed, so sha256(file) == asset_hash ---
    ex = hd["exclusions"][0]
    published = data[:ex["start"]] + data[ex["start"] + ex["length"]:]
    assert hashlib.sha256(published).digest() == asset_hash

    return {
        "published": published,
        "signer_pubkey": point,
        "leaf_issuer": leaf.issuer.rfc4514_string(),
        "fields": {
            "signer_pubkey_x": point[1:33],
            "signer_pubkey_y": point[33:65],
            "asset_hash": asset_hash,
            "signature": signature,
            "tbs": (tbs, MAX_TBS),
            "tbs_len": len(tbs),
            "protected_len": len(protected),
            "actions": (actions, MAX_ACTIONS),
            "actions_len": len(actions),
            "actions_ref_offset": tbs.index(actions_ref, claim_start),
            "hash_data": (hash_data, MAX_HASH_DATA),
            "hash_data_len": len(hash_data),
            "hash_data_ref_offset": tbs.index(hash_data_ref, claim_start),
            "asset_hash_offset": hash_data.index(b"\x64hash\x58\x20" + asset_hash),
            "leaf_tbs_cert": (leaf_tbs_cert, MAX_TBS_CERT),
            "leaf_tbs_cert_len": len(leaf_tbs_cert),
            "leaf_cert_sig": leaf_cert_sig,
            "leaf_spki_offset": leaf_spki_offset,
        },
    }


def prover_toml(fields: dict, names: list, extra: dict = None) -> str:
    """Render `names` (plus `extra`) as Prover.toml; (bytes, max) tuples are zero-padded."""
    values = {n: fields[n] for n in names}
    values.update(extra or {})
    lines = []
    for k, v in values.items():
        if isinstance(v, tuple):
            b, n = v
            assert len(b) <= n, f"{k}: {len(b)} bytes exceeds circuit max {n}"
            v = bytes(b) + bytes(n - len(b))
        if isinstance(v, (bytes, bytearray)):
            lines.append(f"{k} = [{', '.join(str(x) for x in v)}]")
        else:
            lines.append(f'{k} = "{v}"')
    return "\n".join(lines) + "\n"
