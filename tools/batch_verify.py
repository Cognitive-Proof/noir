"""Verifier side: check every published image against the trusted CA.

For each image: is there a valid proof that it is C2PA-signed under the CA,
and if so, does its signed actions assertion declare AI? The verifier sees
only the published images, the proofs and the CA certificate.

Proofs are verified with EXPECTED_VK, the verification key the verifier built
from the trusted_ca_ai_flag circuit itself. A key shipped with the proofs is
never trusted: a proof from any other circuit would verify under its own key.

usage: batch_verify.py PUBLISHED_DIR TRUSTED_CA.pem PROOFS_DIR EXPECTED_VK [--json OUT]
Exit status is 0; the table (and optional JSON) carries the verdicts.
"""
import hashlib
import json
import os
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

published_dir, ca_path, proofs_dir, vk_path = sys.argv[1:5]
expected_vk = open(vk_path, "rb").read()
json_out = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None

ca = x509.load_pem_x509_certificate(open(ca_path, "rb").read())
ca_xy = ca.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]


def verdict(image_path, proof_dir):
    """-> (trusted: bool, has_ai: bool | None, reason)"""
    if not os.path.isfile(f"{proof_dir}/proof"):
        return False, None, "no proof"
    # public inputs, one 32-byte field each: ca_x, ca_y, asset_hash (u8 each), then has_ai
    raw = open(f"{proof_dir}/public_inputs", "rb").read()
    fields = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]
    expected = list(ca_xy + hashlib.sha256(open(image_path, "rb").read()).digest())
    if len(fields) != len(expected) + 1:
        return False, None, "malformed public inputs"
    if fields[:64] != expected[:64]:
        return False, None, "proof is for a different CA"
    if fields[64:-1] != expected[64:]:
        return False, None, "proof is for a different image"
    if fields[-1] not in (0, 1):
        return False, None, "malformed public inputs"
    for shipped in (f"{proofs_dir}/vk", f"{proof_dir}/vk"):
        if os.path.isfile(shipped) and open(shipped, "rb").read() != expected_vk:
            return False, None, "verification key is not the trusted circuit's"
    r = subprocess.run(["bb", "verify", "-k", vk_path, "-p", f"{proof_dir}/proof",
                        "-i", f"{proof_dir}/public_inputs", "-t", "noir-recursive"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, None, "proof invalid"
    return True, bool(fields[-1]), "proof verified"


rows = {}
print(f"{'image':16} {'trusted CA':12} {'AI in actions':14} detail")
for fname in sorted(os.listdir(published_dir)):
    if not fname.endswith(".jpg"):
        continue
    name = fname[:-4]
    trusted, has_ai, reason = verdict(os.path.join(published_dir, fname), f"{proofs_dir}/{name}")
    ai = "-" if has_ai is None else ("YES" if has_ai else "no")
    print(f"{fname:16} {'yes' if trusted else 'NO':12} {ai:14} {reason}")
    rows[name] = {"trusted": trusted, "has_ai": has_ai, "detail": reason}

if json_out:
    json.dump(rows, open(json_out, "w"), indent=2)
