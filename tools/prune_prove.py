"""Pruner side, step 1: one pruned_manifest_no_ai proof per ingredient.

usage: prune_prove.py OUT_DIR INGREDIENT.jpg [INGREDIENT.jpg ...]
  OUT_DIR/vk                      verification key (shared)
  OUT_DIR/<name>/proof            proof
  OUT_DIR/<name>/public_inputs    bb public inputs (H, K)
  OUT_DIR/status.json             proved | not-provable per ingredient
"""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from c2pa_witness import MAX_TBS_PRUNED, extract, prover_toml  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIRCUIT = os.path.join(ROOT, "circuits", "pruned_manifest_no_ai")
BYTECODE = os.path.join(CIRCUIT, "target", "pruned_manifest_no_ai.json")
TARGET = ["-t", "noir-recursive"]

INPUTS = [
    "manifest_hash", "signer_pubkey_x", "signer_pubkey_y",
    "manifest", "manifest_len", "signature", "tbs_len", "protected_len",
    "actions", "actions_len", "actions_ref_offset",
]


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


out, ingredients = sys.argv[1], sys.argv[2:]
shutil.rmtree(out, ignore_errors=True)
os.makedirs(out)
assert run(["nargo", "compile"], cwd=CIRCUIT).returncode == 0, "nargo compile failed"
r = run(["bb", "write_vk", "-b", BYTECODE, "-o", out, *TARGET])
assert r.returncode == 0, r.stderr

status = {}
for path in ingredients:
    name = os.path.basename(path)[:-4]
    t0 = time.time()
    f = extract(path)["fields"]
    toml = prover_toml(f, INPUTS, {"tbs": (f["tbs"][0], MAX_TBS_PRUNED)})
    open(os.path.join(CIRCUIT, f"{name}.toml"), "w").write(toml)
    r = run(["nargo", "execute", "--prover-name", name, name], cwd=CIRCUIT)
    os.remove(os.path.join(CIRCUIT, f"{name}.toml"))
    if r.returncode != 0:
        status[name] = "not-provable"
        print(f"{name:10} NOT provable (AI source type, ingredients, or bad signature)", flush=True)
        continue
    r = run(["bb", "prove", "-b", BYTECODE, "-w", os.path.join(CIRCUIT, "target", f"{name}.gz"),
             "-k", f"{out}/vk", "-o", f"{out}/{name}", *TARGET])
    assert r.returncode == 0, r.stderr
    status[name] = "proved"
    print(f"{name:10} proved in {time.time() - t0:.0f}s  H={f['manifest_hash'].hex()[:16]}…", flush=True)

json.dump(status, open(f"{out}/status.json", "w"), indent=2)
