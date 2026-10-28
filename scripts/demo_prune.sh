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
VK=$OUT/proofs/vk

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
attack() {  # $1 = attack name, $2 = expected verdict text
  $PY tools/prune_build.py $OUT/attack-$1.jpg $OUT/proofs $INGREDIENTS --attack $1 >/dev/null
  local out
  if out=$($PY tools/prune_verify.py $OUT/attack-$1.jpg $CA $VK); then
    echo "UNEXPECTED: attack $1 verified"; exit 1
  fi
  grep -q "$2" <<<"$out" || { echo "UNEXPECTED verdict for $1:"; echo "$out"; exit 1; }
  echo "   $1: rejected ($2)"
}
echo "== dishonest pruner"
attack swap-proofs "different manifest than prunedManifest.hash"
attack wrong-cert "certificate's key is not the proven signer key"
attack own-vk "verification key is not the trusted circuit's"

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
