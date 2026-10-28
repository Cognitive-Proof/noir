"""Regression test: the actions witness must be the actions stored in H.

Rewrites an ingredient manifest so its stored c2pa.actions.v2 box declares
trainedAlgorithmicMedia (fixing up the box lengths so the manifest is still
well formed), recomputes the manifest hash H, but keeps the original clean
actions bytes as the witness. The claim and signature are untouched, so the
witness still matches the signed claim's hash reference; only the binding
between the witness and the committed manifest can reject it.

usage: test_tampered_actions.py INGREDIENT.jpg
Exit status 0 if the circuit rejects the tampered witness.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys

import cbor2

sys.path.insert(0, os.path.dirname(__file__))
from c2pa_witness import MAX_TBS_PRUNED, extract, prover_toml  # noqa: E402
from jumbf import parse_boxes  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIRCUIT = os.path.join(ROOT, "circuits", "pruned_manifest_no_ai")
AI = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"


def grow(buf: bytearray, at: int, delta: int):
    """Add `delta` to the 32-bit LBox at `at`."""
    struct.pack_into(">I", buf, at, struct.unpack_from(">I", buf, at)[0] + delta)


w = extract(sys.argv[1])
f = w["fields"]
manifest = bytearray(f["manifest"][0])

# locate the stored actions box inside the manifest
top = parse_boxes(bytes(manifest), 0, len(manifest))  # jumd + 3 superboxes
store = top[1]
actions_box = next(b for b in store.children if b.label == "c2pa.actions.v2")
cbor_box = actions_box.children[-1]

tampered = cbor2.loads(cbor_box.payload)
tampered["actions"][0]["digitalSourceType"] = AI
new_payload = cbor2.dumps(tampered)
delta = len(new_payload) - len(cbor_box.payload)
manifest[cbor_box.offset + 8:cbor_box.end] = new_payload
for at in (cbor_box.offset, actions_box.offset, store.offset):
    grow(manifest, at, delta)
manifest = bytes(manifest)
assert b"trainedAlgorithmicMedia" in manifest

fields = dict(f)
fields["manifest"] = (manifest, f["manifest"][1])
fields["manifest_len"] = len(manifest)
fields["manifest_hash"] = hashlib.sha256(manifest).digest()  # attacker recomputes H
# fields["actions"] stays the original, clean, signed bytes

abi = json.load(open(os.path.join(CIRCUIT, "target", "pruned_manifest_no_ai.json")))["abi"]
names = [p["name"] for p in abi["parameters"] if p["name"] != "tbs"]
toml = prover_toml(fields, names, {"tbs": (f["tbs"][0], MAX_TBS_PRUNED)})
open(os.path.join(CIRCUIT, "tampered.toml"), "w").write(toml)
r = subprocess.run(["nargo", "execute", "--prover-name", "tampered"], cwd=CIRCUIT,
                   capture_output=True, text=True)
os.remove(os.path.join(CIRCUIT, "tampered.toml"))
if r.returncode == 0:
    print("FAIL: circuit accepted a clean actions witness for a manifest storing AI actions")
    sys.exit(1)
print("ok: circuit rejects a witness that differs from the manifest's stored actions")
