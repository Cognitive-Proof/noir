"""Holder side: one trusted_ca_ai_flag proof per image in a folder.

For every image the holder publishes the manifest-stripped image plus, when
it could be proven against the CA, a proof dir. Images that have no C2PA
manifest or whose signer isn't under the CA get no proof.

usage: batch_prove.py IMAGES_DIR CA.pem OUT_DIR
  OUT_DIR/published/<name>.jpg   images to publish
  OUT_DIR/proofs/<name>/         proof + public_inputs (only when proven)
  OUT_DIR/proofs/vk              verification key shared by every proof
  OUT_DIR/status.json            holder-side log (not published)
"""
import json
import os
import shutil
import subprocess
import sys

from cryptography import x509

sys.path.insert(0, os.path.dirname(__file__))
from c2pa_witness import NoManifest, extract, prover_toml, pubkey_point  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIRCUIT = os.path.join(ROOT, "circuits", "trusted_ca_ai_flag")
BYTECODE = os.path.join(CIRCUIT, "target", "trusted_ca_ai_flag.json")
TARGET = ["-t", "noir-recursive"]

INPUTS = [
    "asset_hash",
    "leaf_tbs_cert", "leaf_tbs_cert_len", "leaf_cert_sig", "leaf_spki_offset",
    "signature", "tbs", "tbs_len", "protected_len",
    "actions", "actions_len", "actions_ref_offset",
    "hash_data", "hash_data_len", "hash_data_ref_offset", "asset_hash_offset",
]


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


images_dir, ca_path, out = sys.argv[1:4]
ca_point = pubkey_point(x509.load_pem_x509_certificate(open(ca_path, "rb").read()).public_key())
ca_fields = {"ca_pubkey_x": ca_point[1:33], "ca_pubkey_y": ca_point[33:65]}

shutil.rmtree(out, ignore_errors=True)
os.makedirs(f"{out}/published")
os.makedirs(f"{out}/proofs")
assert run(["nargo", "compile"], cwd=CIRCUIT).returncode == 0, "nargo compile failed"
r = run(["bb", "write_vk", "-b", BYTECODE, "-o", f"{out}/proofs", *TARGET])
assert r.returncode == 0, r.stderr

status = {}
for fname in sorted(os.listdir(images_dir)):
    if not fname.endswith(".jpg"):
        continue
    name = fname[:-4]
    try:
        w = extract(os.path.join(images_dir, fname))
    except NoManifest:
        shutil.copy(os.path.join(images_dir, fname), f"{out}/published/{fname}")
        status[name] = "no-c2pa"
        print(f"{fname:14} no C2PA manifest, nothing to prove")
        continue
    open(f"{out}/published/{fname}", "wb").write(w["published"])

    open(os.path.join(CIRCUIT, f"{name}.toml"), "w").write(
        prover_toml(w["fields"], INPUTS, ca_fields))
    r = run(["nargo", "execute", "--prover-name", name, name], cwd=CIRCUIT)
    os.remove(os.path.join(CIRCUIT, f"{name}.toml"))
    if r.returncode != 0:
        status[name] = "witness-failed"
        print(f"{fname:14} cannot prove: signer cert ({w['leaf_issuer']}) not under this CA")
        continue

    proof_dir = f"{out}/proofs/{name}"
    r = run(["bb", "prove", "-b", BYTECODE, "-w", os.path.join(CIRCUIT, "target", f"{name}.gz"),
             "-k", f"{out}/proofs/vk", "-o", proof_dir, *TARGET])
    assert r.returncode == 0, r.stderr
    status[name] = "proved"
    print(f"{fname:14} proved")

json.dump(status, open(f"{out}/status.json", "w"), indent=2)
