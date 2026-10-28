#!/usr/bin/env bash
# Pruning demo: 3 ingredients -> composite with pruned ingredient manifests,
# each carrying a ZK proof "manifest H, signed by K, has no AI".
#   SKIP_PROVE=1 reuses existing proofs in out/prune/proofs (~3 min each otherwise)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=".venv/bin/python -I"
CA=fixtures/certs/ca.pem
OUT=out/prune
ING=fixtures/prune/ingredients
INGREDIENTS="$ING/ingr-1.jpg $ING/ingr-2.jpg $ING/ingr-3.jpg"

if [ -z "${SKIP_PROVE:-}" ]; then
  echo "== fixtures"
  scripts/make_prune_fixtures.sh
  echo "== pruner: one proof per ingredient (plus the AI one, which must fail)"
  $PY tools/prune_prove.py $OUT/proofs $INGREDIENTS $ING/ai-ingr.jpg
  grep -q '"ai-ingr": "not-provable"' $OUT/proofs/status.json
fi

echo "== verifier: build its own verification key from the circuit (never the prover's)"
(cd circuits/pruned_manifest_no_ai && nargo compile >/dev/null 2>&1)
bb write_vk -b circuits/pruned_manifest_no_ai/target/pruned_manifest_no_ai.json \
  -o out/prune-verifier -t noir-recursive >/dev/null 2>&1
VK=out/prune-verifier/vk
# a key for some other circuit, for the own-vk attack below
(cd circuits/no_ai_actions && nargo compile >/dev/null 2>&1)
bb write_vk -b circuits/no_ai_actions/target/no_ai_actions.json \
  -o $OUT/decoy-vk -t noir-recursive >/dev/null 2>&1

echo "== pruner: build the composite with pruned ingredients"
$PY tools/prune_build.py $OUT/final.jpg $OUT/proofs $INGREDIENTS
echo "   ingredient manifests left in the final file: $($PY - $OUT/final.jpg <<'EOF'
import sys; sys.path.insert(0, "tools")
from jumbf import jumbf_from_jpeg, parse_boxes
j = jumbf_from_jpeg(open(sys.argv[1], "rb").read())
print(len(parse_boxes(j, 0, len(j))[0].children) - 2)
EOF
)"

echo "== verifier"
$PY tools/prune_verify.py $OUT/final.jpg $CA $VK --reveal $ING/ingr-2.jpg $ING/ai-ingr.jpg

# --- a dishonest pruner signs a valid final manifest; the proofs must catch it
attack() {  # $1 = attack name, $2 = expected verdict text, $3.. = extra prune_build args
  local name=$1 want=$2 out; shift 2
  $PY tools/prune_build.py $OUT/attack-$name.jpg $OUT/proofs $INGREDIENTS --attack $name "$@" >/dev/null
  if out=$($PY tools/prune_verify.py $OUT/attack-$name.jpg $CA $VK); then
    echo "UNEXPECTED: attack $name verified"; exit 1
  fi
  grep -q "$want" <<<"$out" || { echo "UNEXPECTED verdict for $name:"; echo "$out"; exit 1; }
  echo "   $name: rejected ($want)"
}
echo "== dishonest pruner"
attack swap-proofs "different manifest than prunedManifest.hash"
attack wrong-cert "certificate's key is not the proven signer key"
attack own-vk "verification key is not the trusted circuit's" --decoy-vk $OUT/decoy-vk/vk
attack drop-proof "no zero-knowledge proof attached"
# drop a proof and hide a (non-C2PA-typed) copy of the honest store ahead of
# the signed one: the verifier must read the store c2patool validated
attack decoy-store "no zero-knowledge proof attached" --decoy-store $OUT/final.jpg

attack tls-cert "not a C2PA signing credential: no extended key usage accepted"

echo "== ingredients that are not pruned"
# a kept (manifest still in the store) clean ingredient and one with no
# provenance: both are reported, neither needs a proof
$PY tools/prune_build.py $OUT/mixed.jpg $OUT/proofs $INGREDIENTS \
  --ordinary fixtures/signed-camera.jpg --no-provenance fixtures/source.jpg >/dev/null
out=$($PY tools/prune_verify.py $OUT/mixed.jpg $CA $VK) || { echo "UNEXPECTED: mixed rejected"; echo "$out"; exit 1; }
grep -E "kept \(manifest present\)|no provenance|ALL PRUNED" <<<"$out" | sed 's/^/   /'
# a kept ingredient that declares AI still fails: not pruning it can't hide it
$PY tools/prune_build.py $OUT/kept-ai.jpg $OUT/proofs $INGREDIENTS --ordinary $ING/ai-ingr.jpg >/dev/null
if out=$($PY tools/prune_verify.py $OUT/kept-ai.jpg $CA $VK); then echo "UNEXPECTED: kept AI accepted"; exit 1; fi
grep -q "kept ingredient declares AI" <<<"$out" || { echo "$out"; exit 1; }
echo "   kept AI ingredient: rejected (kept ingredient declares AI)"

echo "== a second C2PA store in the file"
$PY tools/inject_store.py $OUT/final.jpg $OUT/attack-drop-proof.jpg $OUT/two-stores.jpg
if $PY tools/prune_verify.py $OUT/two-stores.jpg $CA $VK >/dev/null; then echo "UNEXPECTED"; exit 1; fi
echo "   two C2PA stores: rejected"

echo "== a clean actions witness for a manifest whose stored actions declare AI"
$PY tools/test_tampered_actions.py $ING/ingr-1.jpg

echo "== tampering after signing"
cp $OUT/final.jpg $OUT/tampered.jpg
$PY - $OUT/tampered.jpg <<'EOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read())
i = b.index(b"c2pa.signals.ancestors"); b[i + 200] ^= 1  # flip a bit inside the manifest
open(p, "wb").write(b)
EOF
if $PY tools/prune_verify.py $OUT/tampered.jpg $CA $VK >/dev/null; then echo "UNEXPECTED"; exit 1; fi
echo "   tampered final manifest: rejected"

echo "== all checks passed"
