"""Minimal C2PA v2 manifest writer for JPEG (ES256, single manifest).

Writes the same JUMBF/claim/COSE layout c2pa-rs does, but lets the caller put
arbitrary CBOR into any assertion, including fields c2pa-rs doesn't model yet
(e.g. #2530's prunedManifest / relatedAssertions on c2pa.ingredient.v3).
"""
import hashlib
import os
import struct
import uuid

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

UUID_SUFFIX = bytes.fromhex("00110010800000aa00389b71")
TYPE_STORE = b"c2pa" + UUID_SUFFIX
TYPE_MANIFEST = b"c2ma" + UUID_SUFFIX
TYPE_ASSERTIONS = b"c2as" + UUID_SUFFIX
TYPE_CLAIM = b"c2cl" + UUID_SUFFIX
TYPE_SIGNATURE = b"c2cs" + UUID_SUFFIX
TYPE_CBOR = b"cbor" + UUID_SUFFIX

TOGGLE_LABELLED = 0x03          # requestable + label present
TOGGLE_LABELLED_PRIVATE = 0x13  # ... + private box (the c2sh salt)


def box(tbox: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", 8 + len(payload), tbox) + payload


def superbox(content_type: bytes, label: str, children: list, salt: bytes = None) -> bytes:
    toggles = TOGGLE_LABELLED_PRIVATE if salt else TOGGLE_LABELLED
    desc = content_type + bytes([toggles]) + label.encode() + b"\0"
    if salt:
        desc += box(b"c2sh", salt)
    return box(b"jumb", box(b"jumd", desc) + b"".join(children))


def hashed_uri(label: str, assertion_box: bytes) -> dict:
    """Claim-style reference: SHA-256 over the superbox minus its 8-byte header."""
    return {"url": f"self#jumbf=c2pa.assertions/{label}",
            "hash": hashlib.sha256(assertion_box[8:]).digest()}


class Assertion:
    def __init__(self, label: str, data):
        self.label = label
        self.data = data
        self.salt = os.urandom(16)

    def box(self) -> bytes:
        return superbox(TYPE_CBOR, self.label, [box(b"cbor", cbor2.dumps(self.data))], self.salt)

    def ref(self) -> dict:
        return hashed_uri(self.label, self.box())


def _app11_segments(jumbf: bytes) -> bytes:
    """Split a JUMBF superbox into JPEG APP11 segments (CI 'JP', En 0x0211)."""
    header, body = jumbf[:8], jumbf[8:]
    first = 65533 - 8 - 8          # Le payload - CI/En/Z - this segment's box header
    chunks = [body[:first]] + [body[i:i + first] for i in range(first, len(body), first)]
    out = b""
    for z, chunk in enumerate(chunks, start=1):
        seg = b"JP" + struct.pack(">HI", 0x0211, z) + header + chunk
        out += struct.pack(">HH", 0xFFEB, 2 + len(seg)) + seg
    return out


def _insert_at(jpeg: bytes) -> int:
    """After SOI and an APP0 (JFIF) segment if present, as c2pa-rs does."""
    pos = 2
    if jpeg[2:4] == b"\xff\xe0":
        pos += 2 + struct.unpack(">H", jpeg[4:6])[0]
    return pos


def sign_jpeg(jpeg: bytes, created: list, gathered: list, key_path: str, chain_path: str,
              title: str, generator: dict) -> bytes:
    """Embed a signed manifest made of `created` + `gathered` Assertions (plus a
    c2pa.hash.data that this function adds) into `jpeg`."""
    key = serialization.load_pem_private_key(open(key_path, "rb").read(), None)
    chain = [c.public_bytes(serialization.Encoding.DER)
             for c in x509.load_pem_x509_certificates(open(chain_path, "rb").read())]
    manifest_label = f"urn:c2pa:{uuid.uuid4()}"
    instance_id = f"xmp:iid:{uuid.uuid4()}"
    insert_at = _insert_at(jpeg)
    asset_hash = hashlib.sha256(jpeg).digest()  # == hash of signed file minus the exclusion
    hash_data = Assertion("c2pa.hash.data", None)
    protected = cbor2.dumps({1: -7, 33: chain})

    excl_len = 0
    while True:  # the exclusion length is inside the manifest it measures
        hash_data.data = {"exclusions": [{"start": insert_at, "length": excl_len}],
                          "name": "jumbf manifest", "alg": "sha256", "hash": asset_hash,
                          "pad": b""}  # required by c2pa-rs
        claim = cbor2.dumps({
            "instanceID": instance_id,
            "claim_generator_info": generator,
            "signature": f"self#jumbf=/c2pa/{manifest_label}/c2pa.signature",
            "created_assertions": [a.ref() for a in created + [hash_data]],
            "gathered_assertions": [a.ref() for a in gathered],
            "dc:title": title,
            "alg": "sha256",
        })
        tbs = cbor2.dumps(["Signature1", protected, b"", claim])
        r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
        cose = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, None,
                                              r.to_bytes(32, "big") + s.to_bytes(32, "big")]))
        manifest = superbox(TYPE_MANIFEST, manifest_label, [
            superbox(TYPE_ASSERTIONS, "c2pa.assertions",
                     [a.box() for a in created + gathered + [hash_data]]),
            superbox(TYPE_CLAIM, "c2pa.claim.v2", [box(b"cbor", claim)]),
            superbox(TYPE_SIGNATURE, "c2pa.signature", [box(b"cbor", cose)]),
        ])
        segments = _app11_segments(superbox(TYPE_STORE, "c2pa", [manifest]))
        if len(segments) == excl_len:
            return jpeg[:insert_at] + segments + jpeg[insert_at:]
        excl_len = len(segments)
