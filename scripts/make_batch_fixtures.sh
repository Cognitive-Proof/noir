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
  name=${spec%%:*}; ca=${spec##*:}; base=$CERTS/signer-$name
  [ -f $base.pem ] && continue
  openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out $base.key
  # LibreSSL ignores -subj with prompt=no, so rename the CN in a copy of the config
  sed "s/^CN=.*/CN=Signer $name/" $CERTS/signer.cnf > $base.cnf
  openssl req -new -key $base.key -config $base.cnf \
    | openssl x509 -req -CA $CERTS/$ca.pem -CAkey $CERTS/$ca.key -CAcreateserial \
        -out $base.pem -days 1825 -sha256 -extfile $base.cnf -extensions v3_leaf 2>/dev/null
  cat $base.pem $CERTS/$ca.pem > $base.chain.pem
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

# an edit of camera-a.jpg signed by camera-b: its store holds both manifests
cat > $BATCH/manifests/edited.json <<'EOF'
{
  "alg": "es256",
  "private_key": "../../certs/signer-camera-b.key",
  "sign_cert": "../../certs/signer-camera-b.chain.pem",
  "title": "edited.jpg",
  "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": [
    {"action": "c2pa.color_adjustments", "softwareAgent": {"name": "Darkroom 4"}}]}}]
}
EOF
(cd $BATCH/manifests && c2patool ../images/camera-a.jpg -m edited.json \
  -o ../images/edited.jpg -f >/dev/null)
echo "  edited.jpg  (signer: camera-b, parent: camera-a.jpg)"
