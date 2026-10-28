"""Build Prover.toml for circuits/no_ai_actions from a C2PA-signed JPEG.

Also writes the manifest-stripped JPEG that gets published alongside the
proof: its SHA-256 equals the signed c2pa.hash.data value, which is the
circuit's public `asset_hash`.

usage: make_witness.py SIGNED.jpg OUT_DIR
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from c2pa_witness import extract, prover_toml  # noqa: E402

NO_AI_ACTIONS_INPUTS = [
    "signer_pubkey_x", "signer_pubkey_y", "asset_hash", "signature",
    "tbs", "tbs_len", "protected_len",
    "actions", "actions_len", "actions_ref_offset",
    "hash_data", "hash_data_len", "hash_data_ref_offset", "asset_hash_offset",
]

signed_path, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
w = extract(signed_path)
f = w["fields"]
open(os.path.join(out_dir, "published.jpg"), "wb").write(w["published"])
open(os.path.join(out_dir, "Prover.toml"), "w").write(prover_toml(f, NO_AI_ACTIONS_INPUTS))

# public values a verifier checks the proof against (no private metadata)
json.dump({"signer_pubkey": w["signer_pubkey"].hex(), "asset_hash": f["asset_hash"].hex()},
          open(os.path.join(out_dir, "public.json"), "w"), indent=2)
print(f"tbs={f['tbs_len']} actions={f['actions_len']} hash_data={f['hash_data_len']} -> {out_dir}")
