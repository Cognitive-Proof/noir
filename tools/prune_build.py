"""Pruner side, step 2: build the final composite with pruned ingredients.

For each ingredient the final manifest gets (c2pa-org/specs-core#2530):
  c2pa.ingredient.v3[__n]          prunedManifest {alg, hash}, digitalSourceType,
                                   validationResults, relatedAssertions -> the three below
  c2pa.zero-knowledge-proof.ingredient[__n]   the proof, in the container from
                                   c2pa-org/documentation#318
  c2pa.signals.ingredient[__n]     the ingredient's own signals
  c2pa.signals.ancestors[__n]      its (empty) ancestors' signals
The ingredient manifests themselves are not included.

usage: prune_build.py OUT.jpg PROOFS_DIR INGREDIENT.jpg [INGREDIENT.jpg ...]
         [--attack swap-proofs|wrong-cert|own-vk|drop-proof|decoy-store]
         [--decoy-vk VK] [--decoy-store HONEST_FINAL.jpg]

--attack builds a final manifest the way a dishonest pruner might; it is
still validly signed, and the verifier must catch it. own-vk needs
--decoy-vk, a verification key for some other circuit. decoy-store drops
ingredient 1's proof and hides a retyped copy of an honest final store
(--decoy-store) ahead of the signed one, inside the signed image bytes.
"""
import hashlib
import json
import os
import subprocess
import sys

from PIL import Image

sys.path.insert(0, os.path.dirname(__file__))
from c2pa_builder import Assertion, sign_jpeg  # noqa: E402
from c2pa_witness import extract  # noqa: E402
from inject_store import copied_store  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIRCUIT_SRC = "circuits/pruned_manifest_no_ai/src/main.nr"
REPO_URL = "https://github.com/Cognitive-Proof/noir/blob/c2pa-pruned-ingredients/"
EDITOR = "fixtures/certs/signer-editor"
DST = "http://cv.iptc.org/newscodes/digitalsourcetype/"

STATEMENT = "com.cognitiveproof.c2pa.pruned-manifest-no-ai"
STATEMENT_VERSION = "0.1.0"
PROOF_SYSTEM = "com.aztec.barretenberg.ultrahonk"

# Illustrative mapping onto the conformance rubric's trait names, as used in
# #2530's own examples (no signals rubric list exists yet).
RUBRIC = {"rubricName": "C2PA Asset Signals Rubric (Local)", "rubricVersion": "1.0.0"}
CAPTURE_SOURCES = {"digitalCapture", "negativeFilm", "positiveFilm", "print"}
NON_GENAI_EDITS = {"c2pa.color_adjustments", "c2pa.cropped", "c2pa.resized", "c2pa.filtered"}


def tool_version(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]


def suffix(i):
    return "" if i == 0 else f"__{i}"


def validation_results(path):
    """The ingredient's own results (it has no ingredients, so this is already
    the limited pre-pruning validation #2530 asks for)."""
    r = subprocess.run(["c2patool", path], capture_output=True, text=True)
    return json.loads(r.stdout)["validation_results"]["activeManifest"]


def signals(actions):
    inceptions, transformations = [], []
    for a in actions:
        dst = a.get("digitalSourceType", "").rsplit("/", 1)[-1]
        if a["action"] == "c2pa.created" and dst in CAPTURE_SOURCES:
            inceptions.append({"trait": "inception:signal_capturedMedia", "multiple": False})
        if a["action"] in NON_GENAI_EDITS:
            transformations.append({"trait": "transformation:signal_perceptibleNonGenAI",
                                    "multiple": False})
    return inceptions, transformations


argv = sys.argv[1:]
options = {}
for name in ("--attack", "--decoy-vk", "--decoy-store"):
    if name in argv:
        i = argv.index(name)
        options[name] = argv[i + 1]
        del argv[i:i + 2]
attack, decoy_vk = options.get("--attack"), options.get("--decoy-vk")
if attack == "own-vk" and not decoy_vk:
    sys.exit("--attack own-vk needs --decoy-vk")
if attack == "decoy-store" and "--decoy-store" not in options:
    sys.exit("--attack decoy-store needs --decoy-store")
drop_proof = attack in ("drop-proof", "decoy-store")
out_path, proofs_dir, ingredient_paths = argv[0], argv[1], argv[2:]

statement_spec = {"url": REPO_URL + CIRCUIT_SRC, "alg": "sha256",
                  "hash": hashlib.sha256(open(os.path.join(ROOT, CIRCUIT_SRC), "rb").read()).digest()}
proof_system_version = tool_version(["bb", "--version"])
noir_version = tool_version(["nargo", "--version"]).split("= ")[-1]
vk = open(f"{proofs_dir}/vk", "rb").read()

created, gathered, ingredient_refs = [], [], []
names = [os.path.basename(p)[:-4] for p in ingredient_paths]
for i, (path, name) in enumerate(zip(ingredient_paths, names)):
    w = extract(path)
    f, claim, cert = w["fields"], w["claim"], w["leaf_cert"]
    created_dst = next(a.get("digitalSourceType") for a in w["actions"]["actions"]
                       if a["action"] == "c2pa.created")
    proof_name = name
    proof_hash, signer_key = f["manifest_hash"], w["signer_pubkey"]
    if attack == "swap-proofs":  # attach the next ingredient's whole proof (and its inputs)
        proof_name = names[(i + 1) % len(names)]
        raw = open(f"{proofs_dir}/{proof_name}/public_inputs", "rb").read()
        vals = bytes(raw[k + 31] for k in range(0, len(raw), 32))
        proof_hash, signer_key = vals[:32], b"\x04" + vals[32:96]
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    if attack == "wrong-cert" and i == 0:  # claim a different (trusted) signer
        other = open("fixtures/certs/signer-editor.pem", "rb").read()
        cert_der = x509.load_pem_x509_certificate(other).public_bytes(serialization.Encoding.DER)
    proof_vk = vk
    if attack == "own-vk" and i == 0:  # verification key for some other circuit
        proof_vk = open(decoy_vk, "rb").read()

    s = suffix(i)
    ingredient_label = f"c2pa.ingredient.v3{s}"
    zkp = Assertion(f"c2pa.zero-knowledge-proof.ingredient{s}", {
        "proofSystem": PROOF_SYSTEM,
        "proofSystemVersion": proof_system_version,
        "proofSystemParams": {"verifierTarget": "noir-recursive", "noirVersion": noir_version},
        "statement": STATEMENT,
        "statementVersion": STATEMENT_VERSION,
        "statementSpec": statement_spec,
        "subjects": [{
            # plain JUMBF URI: the ingredient already hash-references this
            # assertion, so a hashed reference back would be circular
            "target": f"self#jumbf=c2pa.assertions/{ingredient_label}",
            "field": "/prunedManifest/hash",
            "visibility": "public",
            "commitmentScheme": "c2pa.pruned-manifest-hash",
        }],
        # [prunedManifest.hash, signer public key (uncompressed P-256 point)]
        "publicInputs": [proof_hash, signer_key],
        "proof": open(f"{proofs_dir}/{proof_name}/proof", "rb").read(),
        "verificationMaterial": [
            {"role": "verificationKey", "value": proof_vk},
            {"role": "com.cognitiveproof.signerCredential", "value": cert_der,
             "dc:format": "application/pkix-cert"},
        ],
    })
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    inceptions, transformations = signals(w["actions"]["actions"])
    sig_ingredient = Assertion(f"c2pa.signals.ingredient{s}", {
        **RUBRIC, "urn": w["manifest_label"],
        **({"assertedBy": {"subject": {"O": org[0].value}}} if org else {}),
        "inceptions": inceptions, "transformations": transformations,
    })
    sig_ancestors = Assertion(f"c2pa.signals.ancestors{s}", {
        **RUBRIC, "inceptions": [], "transformations": [], "incomplete": False,
    })
    ingredient = Assertion(ingredient_label, {
        "dc:title": claim.get("dc:title", f"{name}.jpg"),
        "dc:format": "image/jpeg",
        "relationship": "componentOf",
        "instanceID": claim["instanceID"],
        "digitalSourceType": created_dst,
        "prunedManifest": {"alg": "sha256", "hash": f["manifest_hash"]},
        "validationResults": {"activeManifest": validation_results(path)},
        "relatedAssertions": [zkp.ref(), sig_ingredient.ref(), sig_ancestors.ref()]
        if not (drop_proof and i == 0)  # this ingredient gets no proof
        else [sig_ingredient.ref(), sig_ancestors.ref()],
    })
    created.append(ingredient)
    gathered += [sig_ingredient, sig_ancestors] if drop_proof and i == 0 \
        else [zkp, sig_ingredient, sig_ancestors]
    ingredient_refs.append(ingredient.ref())
    print(f"{name:8} pruned  H={f['manifest_hash'].hex()[:16]}…  signer={cert.subject.rfc4514_string()}")

actions = Assertion("c2pa.actions.v2", {"actions": [
    {"action": "c2pa.created", "digitalSourceType": DST + "compositeCapture"},
    *[{"action": "c2pa.placed", "parameters": {"ingredients": [ref]}} for ref in ingredient_refs],
]})

# the composite: ingredient pixels side by side
srcs = [Image.open(os.path.join(os.path.dirname(os.path.dirname(p)), "src", os.path.basename(p)))
        for p in ingredient_paths]
canvas = Image.new("RGB", (sum(im.width for im in srcs), max(im.height for im in srcs)))
x = 0
for im in srcs:
    canvas.paste(im, (x, 0))
    x += im.width
unsigned = out_path[:-4] + ".unsigned.jpg"
canvas.save(unsigned, quality=90)

jpeg = open(unsigned, "rb").read()
insert_at = None
if attack == "decoy-store":  # retyped honest store first; the signed store goes after it
    from c2pa_builder import _insert_at
    at = _insert_at(jpeg)
    decoy = copied_store(open(options["--decoy-store"], "rb").read(), not_c2pa=True)
    jpeg, insert_at = jpeg[:at] + decoy + jpeg[at:], at + len(decoy)
jpeg = sign_jpeg(jpeg, [actions] + created, gathered,
                 f"{EDITOR}.key", f"{EDITOR}.chain.pem", os.path.basename(out_path),
                 {"name": "noir-c2pa-prune", "version": "0.1.0"}, insert_at)
os.remove(unsigned)
open(out_path, "wb").write(jpeg)
print(f"-> {out_path} ({len(jpeg)} bytes, {len(ingredient_paths)} pruned ingredients"
      f"{', ATTACK ' + attack if attack else ''})")
