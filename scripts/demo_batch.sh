#!/usr/bin/env bash
# Batch demo: six images checked against a trusted CA, with a public AI flag.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=".venv/bin/python -I"
CA=fixtures/certs/ca.pem
ROGUE_CA=fixtures/certs/rogue-ca.pem
OUT=out/batch

echo "== fixtures"
scripts/make_batch_fixtures.sh

echo "== holder: prove each image against the trusted CA"
$PY tools/batch_prove.py fixtures/batch/images $CA $OUT

echo "== verifier: published images + proofs + trusted CA"
$PY tools/batch_verify.py $OUT/published $CA $OUT/proofs --json $OUT/verdicts.json

# expected: image -> trusted, has_ai
$PY - "$OUT/verdicts.json" <<'EOF'
import json, sys
got = {k: (v["trusted"], v["has_ai"]) for k, v in json.load(open(sys.argv[1])).items()}
want = {"camera-a": (True, False), "camera-b": (True, False),
        "ai-gen": (True, True), "ai-edit": (True, True),
        "rogue": (False, None), "plain": (False, None)}
assert got == want, f"verdicts {got} != expected {want}"
print("   verdicts match expected")
EOF

# --- attacks on the verifier -------------------------------------------------
ATTACK=out/batch-attack
rm -rf $ATTACK && cp -R $OUT $ATTACK

expect() {  # $1 = image, $2 = expected detail text, $3.. = verifier args
  local img=$1 want=$2; shift 2
  local line
  line=$($PY tools/batch_verify.py "$@" | grep "^$img.jpg")
  echo "   $line"
  [[ "$line" == *"$want"* ]] || { echo "UNEXPECTED (wanted: $want)"; exit 1; }
}

echo "== attack: modify a published image after proving"
printf 'x' >> $ATTACK/published/camera-a.jpg
expect camera-a "different image" $ATTACK/published $CA $ATTACK/proofs

echo "== attack: reuse camera-a's clean proof for the AI image"
rm -rf $ATTACK/proofs/ai-gen && cp -R $OUT/proofs/camera-a $ATTACK/proofs/ai-gen
expect ai-gen "different image" $ATTACK/published $CA $ATTACK/proofs

echo "== attack: flip ai-edit's public has_ai bit from 1 to 0"
$PY - $ATTACK/proofs/ai-edit/public_inputs <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read())
assert b[-1] == 1; b[-1] = 0; open(p, "wb").write(b)
EOF
expect ai-edit "proof invalid" $ATTACK/published $CA $ATTACK/proofs

echo "== attack: prove the rogue image against the rogue CA (same CA name, other key)"
$PY tools/batch_prove.py fixtures/batch/images $ROGUE_CA out/batch-rogue | grep rogue
mkdir -p $ATTACK/proofs/rogue
cp out/batch-rogue/proofs/rogue/* $ATTACK/proofs/rogue/
expect rogue "different CA" $ATTACK/published $CA $ATTACK/proofs

echo "== verifier trusting the rogue CA instead: genuine proofs don't transfer"
expect camera-a "different CA" $OUT/published $ROGUE_CA $OUT/proofs

echo "== all checks passed"
