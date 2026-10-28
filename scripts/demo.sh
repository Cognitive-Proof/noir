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
done)
for m in camera ai; do $PY tools/make_witness.py fixtures/signed-$m.jpg out/$m; done

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
$PY tools/verify.py out/camera/published.jpg fixtures/certs/signer.pem out/camera

echo "== AI image: prove (must fail)"
if prove ai 2>/dev/null; then echo "UNEXPECTED: AI image proved"; exit 1; fi
echo "   witness rejected, as expected"

echo "== camera proof against a modified image (must fail)"
cp out/camera/published.jpg out/tampered.jpg && printf 'x' >> out/tampered.jpg
if $PY tools/verify.py out/tampered.jpg fixtures/certs/signer.pem out/camera; then exit 1; fi

echo "== camera proof against a different signer (must fail)"
if $PY tools/verify.py out/camera/published.jpg fixtures/certs/ca.pem out/camera; then exit 1; fi

echo "== all checks passed"
