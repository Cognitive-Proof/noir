#!/usr/bin/env bash
# Ingredient images for the pruning demo -> fixtures/prune/ingredients/
#   ingr-1..3: no AI, each signed by a different signer under the trusted CA
#   ai-ingr:   AI-generated (must not be provable)
#   editor:    the signer of the final composite manifest
set -euo pipefail
cd "$(dirname "$0")/.."
PRUNE=fixtures/prune

for spec in camera-a:ca camera-b:ca scanner:ca ai-tool:ca editor:ca; do
  scripts/make_signer.sh ${spec%%:*} ${spec##*:}
done

rm -rf $PRUNE && mkdir -p $PRUNE/ingredients
.venv/bin/python -I tools/prune_fixtures.py $PRUNE | while read -r name signer; do
  (cd $PRUNE/manifests && c2patool ../src/$name.jpg -m $name.json \
    -o ../ingredients/$name.jpg -f >/dev/null)
  echo "  $name.jpg  (signer: $signer)"
done
