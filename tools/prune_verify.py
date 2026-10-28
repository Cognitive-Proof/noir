"""Verifier: check a composite whose ingredient manifests were pruned.

  1. Standard C2PA validation of the final manifest (c2patool), bound to the
     bytes this script reads: the file must hold exactly one C2PA Manifest
     Store, its active manifest must be the one c2patool reports, and the
     claim signature and the claim's hashed URIs are re-checked here.
  2. Every c2pa.ingredient.v3 the signed claim references is one of:
     - kept: its manifest is still in the store (activeManifest). It needs no
       proof: its actions are checked in the clear for an AI digitalSourceType,
       and it must have no ingredients of its own (not followed here).
     - no provenance: no manifest at all. Reported, not covered by any claim.
     - pruned: has prunedManifest (#2530), and must carry a proof: its
     relatedAssertions resolve and hash-match, and one of them is a
     c2pa.zero-knowledge-proof.ingredient (#318) whose
       - statement / verification key are the ones we trust,
       - public manifest hash equals prunedManifest.hash,
       - public signer key equals the key in the attached certificate,
       - certificate was issued by the trusted CA, is in date, and meets the
         C2PA signing-credential profile as c2pa-rs enforces it,
       - proof verifies (bb).
  3. --reveal: match a later-disclosed ingredient's manifest to its entry.

usage: prune_verify.py FINAL.jpg TRUSTED_CA.pem EXPECTED_VK [--reveal INGREDIENT.jpg ...]
Exit status 0 only if there is at least one pruned ingredient, every pruned
ingredient is proven AI-free, and no kept ingredient declares AI.
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
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

sys.path.insert(0, os.path.dirname(__file__))
from jumbf import jumbf_from_jpeg, parse_boxes  # noqa: E402

STATEMENT = "com.cognitiveproof.c2pa.pruned-manifest-no-ai"
PROOF_SYSTEM = "com.aztec.barretenberg.ultrahonk"
ZKP_PREFIX = "c2pa.zero-knowledge-proof.ingredient"
AI_SOURCE_TYPES = ("rainedAlgorithmicMedia", "algorithmicMedia", "compositeSynthetic")

# C2PA signing-credential profile, as c2pa-rs checks it
# (sdk/src/crypto/cose/certificate_profile.rs, valid_eku_oids.cfg)
ANY_EKU = "2.5.29.37.0"
ALLOWED_EKUS = {
    "1.3.6.1.5.5.7.3.4",            # id-kp-emailProtection
    "1.3.6.1.5.5.7.3.36",           # id-kp-documentSigning
    "1.3.6.1.5.5.7.3.8",            # id-kp-timeStamping
    "1.3.6.1.5.5.7.3.9",            # id-kp-OCSPSigning
    "1.3.6.1.4.1.311.76.59.1.9",    # MS C2PA Signing
    "1.3.6.1.4.1.62558.2.1",        # C2PA Signing
}
TIMESTAMPING, OCSP_SIGNING = "1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9"
ALLOWED_SIGNATURE_ALGS = {
    "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4",  # ecdsa-with-SHA256/384/512
    "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",  # sha*WithRSA
    "1.2.840.113549.1.1.10",  # RSASSA-PSS
    "1.3.101.112",            # Ed25519
}
ALLOWED_CURVES = {"secp256r1", "secp384r1", "secp521r1"}
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
store_manifests = {c.label: c for c in parse_boxes(jumbf, 0, len(jumbf))[0].children[1:]}
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


def check_kept(ingr):
    """A non-pruned ingredient whose manifest is still in the store: no proof
    is needed, its actions are read in the clear. -> (ok, verdict)"""
    url = ingr["activeManifest"]["url"]
    m = store_manifests.get(url.split("/c2pa/", 1)[-1].rstrip("/"))
    if m is None or hashlib.sha256(jumbf[m.offset + 8:m.end]).digest() != ingr["activeManifest"]["hash"]:
        return False, "kept manifest missing or altered"
    parts = {c.label: c for c in m.children[1:]}
    claim_box = parts.get("c2pa.claim.v2") or parts.get("c2pa.claim")
    if claim_box is None or "c2pa.assertions" not in parts:
        return False, "kept manifest has no claim"
    claim = cbor2.loads(claim_box.children[-1].payload)
    refs = {r["url"].rsplit("/", 1)[-1]: r["hash"]
            for r in claim.get("created_assertions", []) + claim.get("gathered_assertions", [])
            + claim.get("assertions", [])}
    if any(label.startswith("c2pa.ingredient") for label in refs):
        return False, "kept manifest has ingredients of its own (not followed)"
    boxes = {a.label: a for a in parts["c2pa.assertions"].children[1:]}
    for label, ref_hash in refs.items():
        if not label.startswith("c2pa.actions"):
            continue
        a = boxes.get(label)
        if a is None or hashlib.sha256(jumbf[a.offset + 8:a.end]).digest() != ref_hash:
            return False, f"kept manifest's {label} missing or altered"
        for action in cbor2.loads(a.children[-1].payload).get("actions", []):
            dst = action.get("digitalSourceType", "")
            if any(t in dst for t in AI_SOURCE_TYPES):
                return False, f"kept ingredient declares AI ({dst.rsplit('/', 1)[-1]})"
    return True, "kept (manifest present): no AI declared, checked in the clear"


def credential_problem(cert):
    """Why `cert` isn't an acceptable C2PA claim-signing credential, or None."""
    if cert.version != x509.Version.v3:
        return "not an X.509 v3 certificate"
    exts = {e.oid.dotted_string: e for e in cert.extensions}
    bc = exts.get("2.5.29.19")
    if bc and bc.value.ca:
        return "is a CA certificate"
    if cert.signature_algorithm_oid.dotted_string not in ALLOWED_SIGNATURE_ALGS:
        return "signature algorithm not allowed"
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in ALLOWED_CURVES:
            return "elliptic curve not allowed"
    elif isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            return "RSA key shorter than 2048 bits"
    elif not isinstance(key, ed25519.Ed25519PublicKey):
        return "public key type not allowed"
    ku = exts.get("2.5.29.15")
    if ku is None or not ku.value.digital_signature:
        return "key usage missing digitalSignature"
    if ku.value.key_cert_sign:
        return "key usage allows certificate signing"
    eku = exts.get("2.5.29.37")
    if eku is None:
        return "no extended key usage"
    ekus = {o.dotted_string for o in eku.value}
    if ANY_EKU in ekus:
        return "anyExtendedKeyUsage not allowed"
    if not ekus & ALLOWED_EKUS:
        return "no extended key usage accepted for C2PA signing"
    ts, ocsp = TIMESTAMPING in ekus, OCSP_SIGNING in ekus
    if (ts and ocsp) or ((ts or ocsp) and ekus - {TIMESTAMPING, OCSP_SIGNING}):
        return "invalid combination of extended key usages"
    if any(e.critical and isinstance(e.value, x509.UnrecognizedExtension) for e in cert.extensions):
        return "unrecognised critical extension"
    return None


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
    problem = credential_problem(cert)
    if problem:
        return h, f"signer certificate is not a C2PA signing credential: {problem}"
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


entries, kept, unknown = {}, 0, 0
print(f"\n{'ingredient':22} {'prunedManifest.hash':20} result")
all_ok = final_ok
for label in sorted(l for l in signed_refs if l.startswith("c2pa.ingredient")):
    if label not in assertions or hashlib.sha256(body(label)).digest() != signed_refs[label]:
        all_ok = False
        print(f"{label:22} {'-':20} ✗ ingredient assertion missing or not the one the claim signed")
        continue
    ingr = content(label)
    h = None
    if "prunedManifest" in ingr:
        h, verdict = check_ingredient(label, ingr)
        ok = verdict.startswith("PROVEN")
        if h:
            entries[h] = (label, ingr.get("dc:title"))
    elif "activeManifest" in ingr:
        ok, verdict = check_kept(ingr)
        kept += 1
    else:  # nothing to check: reported, but not covered by any claim
        ok, verdict = True, "no provenance: no C2PA manifest, not covered"
        unknown += 1
    all_ok &= ok
    print(f"{ingr.get('dc:title', label):22} {(h.hex()[:16] + '…') if h else '-':20} "
          f"{'✓' if ok else '✗'} {verdict}")

if not entries:  # nothing was proven; don't report success vacuously
    all_ok = False
    print("no pruned ingredients found")
if kept or unknown:
    print(f"\nalso: {kept} kept ingredient(s) checked in the clear, "
          f"{unknown} without provenance (not covered)")
print("\nALL PRUNED INGREDIENTS PROVEN AI-FREE" if all_ok else "\nNOT ESTABLISHED")

# --- 3. later disclosure -------------------------------------------------------
for path in reveal:
    j, m = active_manifest(path)
    h = hashlib.sha256(j[m.offset + 8:m.end]).digest()
    match = entries.get(h)
    print(f"reveal {os.path.basename(path)}: manifest hash {h.hex()[:16]}… "
          + (f"matches pruned ingredient {match[1]} ({match[0]})" if match else "matches NO pruned ingredient"))

sys.exit(0 if all_ok else 1)
