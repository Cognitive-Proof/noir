"""Verifier: check a composite whose ingredient manifests were pruned.

  1. Standard C2PA validation of the final manifest (c2patool), bound to the
     bytes this script reads: the file must hold exactly one C2PA Manifest
     Store, its active manifest must be the one c2patool reports, and the
     claim signature and the claim's hashed URIs are re-checked here.
  2. For every c2pa.ingredient.v3 the signed claim references and that has
     prunedManifest (#2530): its
     relatedAssertions resolve and hash-match, and one of them is a
     c2pa.zero-knowledge-proof.ingredient (#318) whose
       - statement / verification key are the ones we trust,
       - public manifest hash equals prunedManifest.hash,
       - public signer key equals the key in the attached certificate,
       - certificate was issued by the trusted CA and is in date,
       - proof verifies (bb).
  3. --reveal: match a later-disclosed ingredient's manifest to its entry.

usage: prune_verify.py FINAL.jpg TRUSTED_CA.pem EXPECTED_VK [--reveal INGREDIENT.jpg ...]
Exit status 0 only if every pruned ingredient is proven AI-free.
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

sys.path.insert(0, os.path.dirname(__file__))
from jumbf import jumbf_from_jpeg, parse_boxes  # noqa: E402

STATEMENT = "com.cognitiveproof.c2pa.pruned-manifest-no-ai"
PROOF_SYSTEM = "com.aztec.barretenberg.ultrahonk"
ZKP_PREFIX = "c2pa.zero-knowledge-proof.ingredient"
# failure codes expected for this demo's self-made test certificates
ACCEPTED_FAILURES = {"signingCredential.untrusted"}

args = [a for a in sys.argv[1:]]
reveal = []
if "--reveal" in args:
    reveal = args[args.index("--reveal") + 1:]
    args = args[:args.index("--reveal")]
final_path, ca_path, vk_path = args
ca = x509.load_pem_x509_certificate(open(ca_path, "rb").read())
expected_vk = open(vk_path, "rb").read()


def active_manifest(path):
    j = jumbf_from_jpeg(open(path, "rb").read())
    m = parse_boxes(j, 0, len(j))[0].children[-1]
    return j, m


def reject(reason):
    print(f"final manifest: {reason}")
    print("\nNOT ESTABLISHED")
    sys.exit(1)


# --- 1. the final manifest itself ---------------------------------------------
r = subprocess.run(["c2patool", final_path], capture_output=True, text=True)
try:
    report = json.loads(r.stdout)
    results = report["validation_results"]["activeManifest"]
    active_label = report["active_manifest"]
    signer_serial = int(report["manifests"][active_label]["signature_info"]["cert_serial_number"])
except (ValueError, KeyError):
    reject(f"unreadable: {r.stderr.strip().splitlines()[0] if r.stderr else 'no output'}")
failures = {r["code"] for r in results["failure"]} - ACCEPTED_FAILURES
successes = {r["code"] for r in results["success"]}
print(f"final manifest: claimSignature.validated={'claimSignature.validated' in successes}  "
      f"dataHash.match={'assertion.dataHash.match' in successes}  "
      f"other failures={sorted(failures) or 'none'}")
final_ok = not failures and {"claimSignature.validated", "assertion.dataHash.match"} <= successes

# bind what c2patool validated to the bytes inspected below
try:
    jumbf, manifest = active_manifest(final_path)
except (AssertionError, ValueError) as e:
    reject(str(e))
if manifest.label != active_label:
    reject(f"c2patool validated {active_label} but this file's store ends in {manifest.label}")
parts = {c.label: c for c in manifest.children[1:]}
store = parts["c2pa.assertions"]
assertions = {a.label: a for a in store.children[1:]}
claim_bytes = parts["c2pa.claim.v2"].children[-1].payload
protected, _, _, cose_sig = cbor2.loads(parts["c2pa.signature"].children[-1].payload).value
leaf = x509.load_der_x509_certificate(cbor2.loads(protected)[33][0])
if leaf.serial_number != signer_serial:
    reject("claim signed by a different certificate than c2patool reports")
try:
    leaf.public_key().verify(
        encode_dss_signature(int.from_bytes(cose_sig[:32], "big"), int.from_bytes(cose_sig[32:], "big")),
        cbor2.dumps(["Signature1", protected, b"", claim_bytes]), ec.ECDSA(hashes.SHA256()))
except Exception:
    reject("claim signature does not verify over the bytes inspected")
claim = cbor2.loads(claim_bytes)
signed_refs = {ref["url"].rsplit("/", 1)[-1]: ref["hash"]
               for ref in claim["created_assertions"] + claim.get("gathered_assertions", [])}

# --- 2. each pruned ingredient the signed claim references ---------------------


def body(label):
    a = assertions[label]
    return jumbf[a.offset + 8:a.end]


def content(label):
    return cbor2.loads(assertions[label].children[-1].payload)


def check_ingredient(label, ingr):
    pm = ingr.get("prunedManifest")
    if pm is None or "activeManifest" in ingr or "claimSignature" in ingr:
        return None, "not a pruned ingredient"
    if pm.get("alg") != "sha256" or len(pm.get("hash", b"")) != 32:
        return None, "prunedManifest has no sha256 commitment"
    h = pm["hash"]
    zkp_label = None
    for ref in ingr.get("relatedAssertions", []):
        ref_label = ref["url"].rsplit("/", 1)[-1]
        if ref_label not in assertions or hashlib.sha256(body(ref_label)).digest() != ref["hash"]:
            return h, f"relatedAssertions entry {ref_label} missing or altered"
        if ref_label.startswith(ZKP_PREFIX):
            zkp_label = ref_label
    if zkp_label is None:
        return h, "no zero-knowledge proof attached"
    z = content(zkp_label)
    if z.get("proofSystem") != PROOF_SYSTEM or z.get("statement") != STATEMENT:
        return h, f"unsupported proof {z.get('proofSystem')} / {z.get('statement')}"
    subj = z.get("subjects", [{}])[0]
    if (subj.get("target") != f"self#jumbf=c2pa.assertions/{label}"
            or subj.get("field") != "/prunedManifest/hash"):
        return h, "proof's subject is a different ingredient"
    proof_hash, signer_key = z["publicInputs"]
    if proof_hash != h:
        return h, "proof is about a different manifest than prunedManifest.hash"
    material = {m["role"]: m["value"] for m in z["verificationMaterial"]}
    if material.get("verificationKey") != expected_vk:
        return h, "verification key is not the trusted circuit's"
    cert = x509.load_der_x509_certificate(material["com.cognitiveproof.signerCredential"])
    cert_key = cert.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint)
    if cert_key != signer_key:
        return h, "certificate's key is not the proven signer key"
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return h, "signer certificate not issued by the trusted CA"
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        return h, "signer certificate expired or not yet valid"
    with tempfile.TemporaryDirectory() as d:
        open(f"{d}/proof", "wb").write(z["proof"])
        open(f"{d}/vk", "wb").write(material["verificationKey"])
        # bb public inputs: one 32-byte field element per byte of H, x, y
        open(f"{d}/public_inputs", "wb").write(
            b"".join(bytes(31) + bytes([b]) for b in h + signer_key[1:]))
        r = subprocess.run(["bb", "verify", "-k", f"{d}/vk", "-p", f"{d}/proof",
                            "-i", f"{d}/public_inputs", "-t", "noir-recursive"],
                           capture_output=True, text=True)
    if r.returncode != 0:
        return h, "proof does not verify"
    return h, f"PROVEN no AI, signed by {cert.subject.rfc4514_string()}"


entries = {}
print(f"\n{'ingredient':22} {'prunedManifest.hash':20} result")
all_ok = final_ok
for label in sorted(l for l in signed_refs if l.startswith("c2pa.ingredient")):
    if label not in assertions or hashlib.sha256(body(label)).digest() != signed_refs[label]:
        all_ok = False
        print(f"{label:22} {'-':20} ✗ ingredient assertion missing or not the one the claim signed")
        continue
    ingr = content(label)
    h, verdict = check_ingredient(label, ingr)
    ok = verdict.startswith("PROVEN")
    all_ok &= ok
    if h:
        entries[h] = (label, ingr.get("dc:title"))
    print(f"{ingr.get('dc:title', label):22} {(h.hex()[:16] + '…') if h else '-':20} "
          f"{'✓' if ok else '✗'} {verdict}")

if not entries:  # nothing was proven; don't report success vacuously
    all_ok = False
    print("no pruned ingredients found")
print("\nALL PRUNED INGREDIENTS PROVEN AI-FREE" if all_ok else "\nNOT ESTABLISHED")

# --- 3. later disclosure -------------------------------------------------------
for path in reveal:
    j, m = active_manifest(path)
    h = hashlib.sha256(j[m.offset + 8:m.end]).digest()
    match = entries.get(h)
    print(f"reveal {os.path.basename(path)}: manifest hash {h.hex()[:16]}… "
          + (f"matches pruned ingredient {match[1]} ({match[0]})" if match else "matches NO pruned ingredient"))

sys.exit(0 if all_ok else 1)
