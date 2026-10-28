"""Verifier for the no_ai_actions proof.

Checks that the proof's public inputs are (trusted signer key, sha256 of the
published image) and then runs `bb verify` with EXPECTED_VK, the verification
key the verifier built from the circuit itself. A key shipped next to the
proof is never trusted: a proof from any other circuit would verify under its
own key. The verifier never sees the manifest.

usage: verify.py PUBLISHED.jpg TRUSTED_SIGNER.pem PROOF_DIR EXPECTED_VK
"""
import hashlib
import os
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

image_path, cert_path, proof_dir, vk_path = sys.argv[1:5]

cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
point = cert.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
expected = point[1:65] + hashlib.sha256(open(image_path, "rb").read()).digest()

# public inputs: one 32-byte field element per u8, in parameter order
raw = open(f"{proof_dir}/public_inputs", "rb").read()
fields = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]
if fields != list(expected):
    sys.exit("REJECT: proof is not about this image and/or this signer")

supplied_vk = f"{proof_dir}/vk"
if os.path.exists(supplied_vk) and open(supplied_vk, "rb").read() != open(vk_path, "rb").read():
    sys.exit("REJECT: verification key is not the trusted circuit's")
r = subprocess.run(["bb", "verify", "-k", vk_path, "-p", f"{proof_dir}/proof",
                    "-i", f"{proof_dir}/public_inputs", "-t", "noir-recursive"],
                   capture_output=True, text=True)
if r.returncode != 0:
    sys.exit("REJECT: proof invalid\n" + r.stderr)
print("ACCEPT: image is signed by the trusted key and its C2PA actions "
      "declare no AI-generated source")
