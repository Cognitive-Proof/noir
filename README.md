# Noir-C2PA: selective disclosure over C2PA manifests

Two circuits:

| Circuit | Public inputs | Proves |
|---|---|---|
| [`trusted_ca_ai_flag`](#batch-trusted-ca--ai-flag) | CA key, image hash → **`has_ai`** | Signed by *some* cert under the trusted CA; reveals one bit: AI in actions or not |
| [`no_ai_actions`](#single-image-no-ai-proof) | signer key, image hash | Signed by this exact key, and no AI in actions (AI images can't be proven) |

## Batch: trusted CA + AI flag

```bash
scripts/demo_batch.sh
```

[`circuits/trusted_ca_ai_flag`](circuits/trusted_ca_ai_flag/src/main.nr) proves, for one image:

> The image with SHA-256 `asset_hash` has a C2PA claim signed by a certificate that the CA `ca_pubkey` issued.
> `has_ai` (public output) says whether that claim's `c2pa.actions` declares an AI-generated source type.

The signer stays hidden, because the leaf certificate and its key are private witnesses. So does everything else in the manifest.

**Batching is one proof per image.** All images share one verification key.
- [tools/batch_prove.py](tools/batch_prove.py) (holder side) proves every image in a folder.
- [tools/batch_verify.py](tools/batch_verify.py) (verifier side) checks each published image and prints a table:

```
image            trusted CA   AI in actions  detail
ai-edit.jpg      yes          YES            proof verified
ai-gen.jpg       yes          YES            proof verified
camera-a.jpg     yes          no             proof verified
camera-b.jpg     yes          no             proof verified
plain.jpg        NO           -              no proof
rogue.jpg        NO           -              no proof
```

Fixtures ([scripts/make_batch_fixtures.sh](scripts/make_batch_fixtures.sh)):
- Three signers under the trusted CA (`camera-a`, `camera-b`, `ai-tool`).
- A **rogue CA that copies the trusted CA's exact name** but has its own key.
- `ai-edit` is a real camera capture, later edited with `compositeWithTrainedAlgorithmicMedia` (generative fill).
- `plain` has no manifest.

The demo also runs these attacks, and all of them are rejected:

| Attack | Result |
|---|---|
| Modify a published image after proving | proof is for a different image |
| Reuse a clean image's proof for an AI image | proof is for a different image |
| Flip the public `has_ai` bit from 1 to 0 | proof invalid |
| Prove the rogue image under the look-alike rogue CA | proof is for a different CA |

**What the circuit adds on top of `no_ai_actions`:**
1. ES256 check that the CA signed the leaf certificate (`sha256_var` over the certificate's signed portion).
2. The leaf's P-256 key is read from the SubjectPublicKeyInfo (SPKI) at a prover-supplied offset, after checking the fixed 27-byte SPKI prefix.
3. That key must verify the claim signature.
4. The AI substring counts become the `has_ai` output instead of a failed assertion.

Size: about 630k gates (2^20 circuit). Proving takes about 3–4 s per image; proof generation for the 6-image batch takes about 18 s in total.

**Limitations beyond those listed for the single-image circuit:**
- The CA must sign the leaf directly: no intermediate certificates.
- Certificate validity dates, EKU and `CA:FALSE` aren't checked in the circuit.
- The SPKI is found by pattern match. That's sound only if the CA never signs certificates with a second P-256 key elsewhere in the signed bytes.
- `has_ai` is per image. The verifier learns which images contain AI, but not which signer or which actions.

## Single image: "no AI" proof

A Noir circuit that proves, about a C2PA-signed image:

> The image with SHA-256 `asset_hash` has a C2PA claim signed by `signer_pubkey`,
> and that claim's `c2pa.actions` assertion declares no AI-generated digital source type.

All other metadata stays private: GPS, author, title, timestamps, thumbnail, cert chain and the list of actions.
The verifier gets only the manifest-stripped image, a 14.6 KB proof and the signer's public key.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install cbor2 cryptography pillow
scripts/demo.sh
```

Requires `nargo` 1.0.0-beta.25, `bb` 5.0 and `c2patool` 0.27. The demo:

1. Signs `fixtures/source.jpg` twice with an ES256 test cert: a camera capture (`digitalCapture`, with GPS/author EXIF) and an AI image (`trainedAlgorithmicMedia`).
2. Extracts witnesses ([tools/make_witness.py](tools/make_witness.py)) and writes `published.jpg`, the image with its manifest removed.
3. Proves the camera image, then verifies it with [tools/verify.py](tools/verify.py). The verifier passes in `EXPECTED_VK`, the verification key it built from the circuit itself, and never trusts a key shipped with a proof.
4. Confirms these all fail: proving the AI image, verifying against a modified image, verifying against a different signer, and a "proof" that the AI image is clean from [a decoy circuit](circuits/decoy_no_ai_actions/src/main.nr) that checks nothing.

Circuit: about 480k UltraHonk gates (2^19). Proving takes about 3 s on an M-series laptop, with about 1.2 GB peak memory.

## What the circuit checks ([main.nr](circuits/no_ai_actions/src/main.nr))

| Step | Check |
|---|---|
| 1 | The private `tbs` is a well-formed COSE `Sig_structure` `["Signature1", protected, h'', claim]`, and its SHA-256 carries a valid ES256 signature under the public `signer_pubkey`. |
| 2 | The claim contains the hashed-uri `{"url": "self#jumbf=c2pa.assertions/c2pa.actions.v2", "hash": sha256(actions_box)}`. |
| 2b | The claim refers to `c2pa.assertions/c2pa.actions*` exactly once, so a prover can't pick a clean actions assertion when there is more than one. |
| 3 | The actions assertion bytes contain none of: `trainedAlgorithmicMedia`, `compositeWithTrainedAlgorithmicMedia`, `algorithmicMedia`, `compositeSynthetic`. |
| 4 | The claim references `c2pa.hash.data`, whose `hash` field equals the public `asset_hash`. |

Step 4 is what ties the proof to the image. For a JPEG, `c2pa.hash.data` hashes the file with the manifest segments excluded, so `sha256(published.jpg) == asset_hash`. The verifier recomputes it from the pixels they actually received.

### C2PA byte details this relies on
- An assertion's hash in the claim is SHA-256 over its JUMBF superbox **minus the 8-byte box header** (the `jumd` description box followed by the content box).
- The signature is ES256 over the COSE `Sig_structure` with a detached payload (the claim bytes). bb accepts only low-s signatures, so the witness generator normalises `s → n − s`.

## Limitations / next steps

- **The signer's key is public.** Next step: verify the leaf certificate under a public CA key inside the circuit (one more SHA-256 plus ECDSA check), which hides which device or tool signed the image.
- **Policy is a substring scan over the actions assertion.** It doesn't parse CBOR. A hostile signer could slip past it with indefinite-length (chunked) CBOR strings. That is acceptable when you trust the signer, which you already must.
- **Pattern matching instead of parsing.** Steps 2 and 4 find byte patterns at prover-chosen offsets. Text a signer embeds (such as a title) could in principle imitate a hashed-uri. The single-actions-reference check (step 2b) blocks the cherry-picking version of this.
- **Only the active manifest is checked.** Ingredient (parent) manifests aren't. Their AI history would need recursive proofs.
- **Narrow input shapes.** It handles ES256 only, claim v2 / `c2pa.actions.v2`, JPEG, and a Sig_structure up to 2048 bytes. Protected header and claim must each be 256–65535 bytes. No timestamp or revocation checking.
- Uses test certificates only (`fixtures/certs`). c2patool reports them as `signingCredential.untrusted`, which is expected.
