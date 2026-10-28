#!/usr/bin/env bash
# Certs + six test images for the batch demo -> fixtures/batch/images/
#   trusted CA = fixtures/certs/ca.*, rogue CA = fixtures/certs/rogue-ca.*
set -euo pipefail
cd "$(dirname "$0")/.."
CERTS=fixtures/certs
BATCH=fixtures/batch

# rogue root CA: impersonates the trusted CA's exact name (same ca.cnf), but
# with its own key. Trust is by key, so its signers must still be rejected.
if [ ! -f $CERTS/rogue-ca.pem ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/rogue-ca.key
  openssl req -new -x509 -key $CERTS/rogue-ca.key -out $CERTS/rogue-ca.pem -days 3650 \
    -config $CERTS/ca.cnf -sha256
fi

# leaf signers: name:issuing-CA
for spec in camera-a:ca camera-b:ca ai-tool:ca rogue:rogue-ca; do
  scripts/make_signer.sh ${spec%%:*} ${spec##*:}
done

rm -rf $BATCH && mkdir -p $BATCH/images
.venv/bin/python -I tools/batch_fixtures.py $BATCH | while read -r name signer; do
  if [ "$signer" = "-" ]; then
    cp $BATCH/src/$name.jpg $BATCH/images/$name.jpg
  else
    (cd $BATCH/manifests && c2patool ../src/$name.jpg -m $name.json \
      -o ../images/$name.jpg -f >/dev/null)
  fi
  echo "  $name.jpg  (signer: $signer)"
done
