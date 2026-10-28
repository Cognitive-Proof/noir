#!/usr/bin/env bash
# Create an ES256 leaf signer under a CA, if it doesn't exist yet.
#   usage: make_signer.sh NAME CA    (CA = ca | rogue-ca)
# -> fixtures/certs/signer-NAME.{key,pem,chain.pem,cnf}
set -euo pipefail
cd "$(dirname "$0")/.."
CERTS=fixtures/certs
name=$1; ca=$2; base=$CERTS/signer-$name
[ -f $base.pem ] && exit 0
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out $base.key
# LibreSSL ignores -subj with prompt=no, so rename the CN in a copy of the config
sed "s/^CN=.*/CN=Signer $name/" $CERTS/signer.cnf > $base.cnf
openssl req -new -key $base.key -config $base.cnf \
  | openssl x509 -req -CA $CERTS/$ca.pem -CAkey $CERTS/$ca.key -CAcreateserial \
      -out $base.pem -days 1825 -sha256 -extfile $base.cnf -extensions v3_leaf 2>/dev/null
cat $base.pem $CERTS/$ca.pem > $base.chain.pem
