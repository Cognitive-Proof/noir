#!/usr/bin/env bash
# End-to-end: sign -> witness -> prove -> verify, plus negative cases.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=".venv/bin/python -I"
CIRCUIT=circuits/no_ai_actions
VK_DIR=out/vk

# --- holder side -------------------------------------------------------------
(cd fixtures && for m in camera ai; do
  c2patool source.jpg -m manifests/$m.json -o signed-$m.jpg -f >/dev/null
done
# an edit of the camera photo: its store holds the parent manifest + the active one
c2patool signed-camera.jpg -m manifests/edit.json -o signed-edited.jpg -f >/dev/null)
for m in camera ai edited; do $PY tools/make_witness.py fixtures/signed-$m.jpg out/$m; done

(cd $CIRCUIT && nargo compile)
mkdir -p $VK_DIR
bb write_vk -b $CIRCUIT/target/no_ai_actions.json -o $VK_DIR -t noir-recursive >/dev/null 2>&1

prove() {  # $1 = fixture name (steps chained: set -e is off inside `if`)
  rm -f $CIRCUIT/target/$1.gz out/$1/proof &&
  cp out/$1/Prover.toml $CIRCUIT/$1.toml &&
  (cd $CIRCUIT && nargo execute --prover-name $1 $1 >/dev/null) &&
  bb prove -b $CIRCUIT/target/no_ai_actions.json -w $CIRCUIT/target/$1.gz \
    -k $VK_DIR/vk -o out/$1 -t noir-recursive >/dev/null 2>&1 &&
  cp $VK_DIR/vk out/$1/vk
}

echo "== camera photo: prove"
prove camera
echo "== camera photo: verify"
$PY tools/verify.py out/camera/published.jpg fixtures/certs/signer.pem out/camera $VK_DIR/vk

echo "== edited photo, two manifests in its store: prove and verify the active one"
prove edited
$PY tools/verify.py out/edited/published.jpg fixtures/certs/signer.pem out/edited $VK_DIR/vk

echo "== AI image: prove (must fail)"
if prove ai 2>/dev/null; then echo "UNEXPECTED: AI image proved"; exit 1; fi
echo "   witness rejected, as expected"

echo "== camera proof against a modified image (must fail)"
cp out/camera/published.jpg out/tampered.jpg && printf 'x' >> out/tampered.jpg
if $PY tools/verify.py out/tampered.jpg fixtures/certs/signer.pem out/camera $VK_DIR/vk; then exit 1; fi

echo "== camera proof against a different signer (must fail)"
if $PY tools/verify.py out/camera/published.jpg fixtures/certs/ca.pem out/camera $VK_DIR/vk; then exit 1; fi

echo "== AI image proven by a decoy circuit that checks nothing (must fail)"
DECOY=circuits/decoy_no_ai_actions
head -3 out/ai/Prover.toml > $DECOY/Prover.toml
(cd $DECOY && nargo execute w >/dev/null) && rm $DECOY/Prover.toml
rm -rf out/decoy && bb prove -b $DECOY/target/decoy_no_ai_actions.json -w $DECOY/target/w.gz \
  -o out/decoy -t noir-recursive --write_vk >/dev/null 2>&1
if $PY tools/verify.py out/ai/published.jpg fixtures/certs/signer.pem out/decoy $VK_DIR/vk; then exit 1; fi
rm out/decoy/vk  # same proof without its own key: fails under the pinned key
if out=$($PY tools/verify.py out/ai/published.jpg fixtures/certs/signer.pem out/decoy $VK_DIR/vk 2>&1); then exit 1; fi
echo "$out" | head -1

echo "== all checks passed"
