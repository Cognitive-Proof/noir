// Proof for a pruned C2PA ingredient manifest (c2pa-org/specs-core#2530):
//
//   "The C2PA Manifest whose JUMBF superbox contents hash to `manifest_hash`
//    (the ingredient's `prunedManifest.hash`) has a claim signed by
//    `signer_pubkey`, that claim has no ingredients of its own, and its
//    c2pa.actions assertion declares no AI-generated digitalSourceType."
//
// The manifest itself (assertions, thumbnail, EXIF/GPS, claim, certificate
// chain) stays private. The claim and signature are located by walking the
// manifest's own JUMBF box structure, so bytes hidden elsewhere in the
// manifest (e.g. inside the thumbnail) can't stand in for them.
use sha256::sha256_var;

// Largest manifest the circuit accepts (thumbnail included)
global MAX_MANIFEST: u32 = 57344;
global MAX_TBS: u32 = 2112;
global MAX_PROTECTED: u32 = 1280;
global MAX_CLAIM: u32 = 768;
global MAX_ACTIONS: u32 = 512;

// COSE Sig_structure prefix: array(4), tstr(10) "Signature1"
global SIG1_PREFIX: [u8; 12] = [0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31];
// Offset of the protected-header bytes / claim bytes inside the Sig_structure
global PROTECTED_START: u32 = 15;
global CLAIM_HEADER_LEN: u32 = 4; // 0x40 (empty aad) + 0x59 len16 (claim)

global JUMB: [u8; 4] = "jumb".as_bytes();
global JUMD: [u8; 4] = "jumd".as_bytes();
global CBOR: [u8; 4] = "cbor".as_bytes();
// JUMBF labels (null-terminated) of the manifest's three top-level superboxes
global LABEL_ASSERTIONS: [u8; 16] = "c2pa.assertions\0".as_bytes();
global LABEL_CLAIM: [u8; 14] = "c2pa.claim.v2\0".as_bytes();
global LABEL_SIGNATURE: [u8; 15] = "c2pa.signature\0".as_bytes();
// superbox header (8) + jumd header (8) + content-type UUID (16) + toggles (1)
global LABEL_AT: u32 = 33;

// COSE_Sign1 as c2pa-rs writes it: tag 18, array(4), protected bstr (len16)
global COSE_HEAD: [u8; 3] = [0xd2, 0x84, 0x59];
// unprotected header {"pad": bstr (len16)}
global PAD_HEAD: [u8; 6] = [0xa1, 0x63, 0x70, 0x61, 0x64, 0x59];
// nil payload (detached), signature bstr(64)
global SIG_HEAD: [u8; 3] = [0xf6, 0x58, 0x40];

// secp256r1 group order, big-endian
global P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

global ACTIONS_URL: [u8; 42] = "self#jumbf=c2pa.assertions/c2pa.actions.v2".as_bytes();
// Every actions assertion label (c2pa.actions, c2pa.actions.v2, c2pa.actions__1, ...)
global ACTIONS_PREFIX: [u8; 28] = "c2pa.assertions/c2pa.actions".as_bytes();
// Every ingredient assertion label (c2pa.ingredient, .v2, .v3, __1, ...)
global INGREDIENT_PREFIX: [u8; 31] = "c2pa.assertions/c2pa.ingredient".as_bytes();

// IPTC digitalSourceType values treated as AI / synthetic generation.
// "rainedAlgorithmicMedia" covers trainedAlgorithmicMedia and
// compositeWithTrainedAlgorithmicMedia.
global AI_TRAINED: [u8; 22] = "rainedAlgorithmicMedia".as_bytes();
global AI_ALGORITHMIC: [u8; 16] = "algorithmicMedia".as_bytes();
global AI_COMPOSITE_SYNTHETIC: [u8; 18] = "compositeSynthetic".as_bytes();

fn main(
    manifest_hash: pub [u8; 32],
    signer_pubkey_x: pub [u8; 32],
    signer_pubkey_y: pub [u8; 32],
    manifest: [u8; MAX_MANIFEST],
    manifest_len: u32,
    signature: [u8; 64],
    tbs: [u8; MAX_TBS],
    tbs_len: u32,
    protected_len: u32,
    actions: [u8; MAX_ACTIONS],
    actions_len: u32,
    actions_ref_offset: u32,
) {
    // 1. The commitment: prunedManifest.hash is SHA-256 over the manifest
    //    superbox contents (everything after its 8-byte header).
    assert(manifest_len <= MAX_MANIFEST);
    assert(sha256_var(manifest, manifest_len) == manifest_hash);

    // 2. Walk the top-level boxes: jumd, c2pa.assertions, c2pa.claim.v2,
    //    c2pa.signature, ending exactly at the end of the manifest.
    assert_bytes_at(manifest, 4, JUMD);
    let assertions_at = be32_at(manifest, 0);
    let claim_box_at = assertions_at + superbox_len(manifest, assertions_at, LABEL_ASSERTIONS);
    let sig_box_at = claim_box_at + superbox_len(manifest, claim_box_at, LABEL_CLAIM);
    assert(sig_box_at + superbox_len(manifest, sig_box_at, LABEL_SIGNATURE) == manifest_len);
    let (claim_at, claim_len) = cbor_payload(manifest, claim_box_at);
    let (cose_at, cose_len) = cbor_payload(manifest, sig_box_at);

    // 3. COSE_Sign1 in the signature box: protected header, pad, signature.
    assert_bytes_at(manifest, cose_at, COSE_HEAD);
    assert(be16(manifest[cose_at + 3], manifest[cose_at + 4]) == protected_len);
    let protected_at = cose_at + 5;
    let pad_head_at = protected_at + protected_len;
    assert_bytes_at(manifest, pad_head_at, PAD_HEAD);
    let pad_len = be16(manifest[pad_head_at + 6], manifest[pad_head_at + 7]);
    let sig_head_at = pad_head_at + 8 + pad_len;
    assert_bytes_at(manifest, sig_head_at, SIG_HEAD);
    let sig_at = sig_head_at + 3;
    assert(sig_at + 64 == cose_at + cose_len);
    assert_same_signature(manifest, sig_at, signature);

    // 4. The Sig_structure ["Signature1", protected, h'', claim] is built
    //    from exactly those protected-header and claim bytes.
    let claim_start = check_sig_structure(tbs, tbs_len, protected_len);
    assert(protected_len <= MAX_PROTECTED);
    assert(claim_len <= MAX_CLAIM);
    assert(tbs_len - claim_start == claim_len);
    for i in 0..MAX_PROTECTED {
        if i < protected_len {
            assert(tbs[PROTECTED_START + i] == manifest[protected_at + i]);
        }
    }
    for i in 0..MAX_CLAIM {
        if i < claim_len {
            let at = claim_start + i;
            assert(tbs[at] == manifest[claim_at + i]);
        }
    }

    // 5. The claim signature: ES256 under the public signer key.
    assert(std::ecdsa_secp256r1::verify_signature(
        signer_pubkey_x,
        signer_pubkey_y,
        signature,
        sha256_var(tbs, tbs_len),
    ));

    // 6. No ancestors: the claim references no ingredient assertion.
    assert(count_in_range(tbs, claim_start, tbs_len, INGREDIENT_PREFIX) == 0);

    // 7. The claim references exactly one actions assertion, by hash ...
    let actions_hash = sha256_var(actions, actions_len);
    assert_hashed_uri(tbs, tbs_len, claim_start, actions_ref_offset, ACTIONS_URL, actions_hash);
    assert(count_in_range(tbs, claim_start, tbs_len, ACTIONS_PREFIX) == 1);

    // 8. ... and it declares no AI digital source type.
    assert(count_in_range(actions, 0, actions_len, AI_TRAINED) == 0);
    assert(count_in_range(actions, 0, actions_len, AI_ALGORITHMIC) == 0);
    assert(count_in_range(actions, 0, actions_len, AI_COMPOSITE_SYNTHETIC) == 0);
}

/// Length of the JUMBF superbox at `at`, after checking it is a superbox
/// whose description box carries `label`.
fn superbox_len<let L: u32>(manifest: [u8; MAX_MANIFEST], at: u32, label: [u8; L]) -> u32 {
    assert_bytes_at(manifest, at + 4, JUMB);
    assert_bytes_at(manifest, at + 12, JUMD);
    assert_bytes_at(manifest, at + LABEL_AT, label);
    be32_at(manifest, at)
}

/// (offset, length) of the payload of the `cbor` box that follows the
/// description box inside the superbox at `at`; it must fill the superbox.
fn cbor_payload(manifest: [u8; MAX_MANIFEST], at: u32) -> (u32, u32) {
    let cbor_box_at = at + 8 + be32_at(manifest, at + 8);
    assert_bytes_at(manifest, cbor_box_at + 4, CBOR);
    let cbor_box_len = be32_at(manifest, cbor_box_at);
    assert(cbor_box_at + cbor_box_len == at + be32_at(manifest, at));
    (cbor_box_at + 8, cbor_box_len - 8)
}

/// The signature passed to the verifier is the one in the manifest, with s
/// either unchanged or replaced by n - s (barretenberg only accepts low-s).
fn assert_same_signature(manifest: [u8; MAX_MANIFEST], sig_at: u32, signature: [u8; 64]) {
    for i in 0..32 {
        assert(signature[i] == manifest[sig_at + i]);
    }
    let mut same = true;
    let mut carry: u16 = 0;
    let mut sums_to_n = true;
    for k in 0..32 {
        let i = 31 - k;
        let s = manifest[sig_at + 32 + i];
        let s_low = signature[32 + i];
        same &= s == s_low;
        let sum = (s as u16) + (s_low as u16) + carry;
        sums_to_n &= (sum % 256) as u8 == P256_N[i];
        carry = sum / 256;
    }
    assert(same | (sums_to_n & (carry == 0)));
}

fn be32_at(buf: [u8; MAX_MANIFEST], at: u32) -> u32 {
    ((buf[at] as u32) << 24)
        | ((buf[at + 1] as u32) << 16)
        | ((buf[at + 2] as u32) << 8)
        | (buf[at + 3] as u32)
}

/// Checks the fixed CBOR framing of the Sig_structure and returns where the
/// claim bytes start. Supports protected headers and claims of 256..65535
/// bytes (0x59 two-byte length), which is what c2pa-rs produces with a cert chain.
fn check_sig_structure(tbs: [u8; MAX_TBS], tbs_len: u32, protected_len: u32) -> u32 {
    assert(tbs_len <= MAX_TBS);
    assert_bytes_at(tbs, 0, SIG1_PREFIX);
    assert(tbs[12] == 0x59);
    assert(be16(tbs[13], tbs[14]) == protected_len);

    let aad_at = PROTECTED_START + protected_len;
    let claim_start = aad_at + CLAIM_HEADER_LEN;
    assert(claim_start <= tbs_len);
    assert(tbs[aad_at] == 0x40);
    assert(tbs[aad_at + 1] == 0x59);
    assert(be16(tbs[aad_at + 2], tbs[aad_at + 3]) == tbs_len - claim_start);
    claim_start
}

/// Asserts the claim contains the hashed-uri map {"url": url, "hash": digest}
/// at `offset`, entirely inside the claim bytes.
fn assert_hashed_uri<let U: u32>(
    tbs: [u8; MAX_TBS],
    tbs_len: u32,
    claim_start: u32,
    offset: u32,
    url: [u8; U],
    digest: [u8; 32],
) {
    // a2 63 "url" 78 <U> url 64 "hash" 58 20 digest
    let mut expected = [0; U + 46];
    let head = [0xa2, 0x63, 0x75, 0x72, 0x6c, 0x78, U as u8];
    for i in 0..7 {
        expected[i] = head[i];
    }
    for i in 0..U {
        expected[7 + i] = url[i];
    }
    let mid = [0x64, 0x68, 0x61, 0x73, 0x68, 0x58, 0x20];
    for i in 0..7 {
        expected[7 + U + i] = mid[i];
    }
    for i in 0..32 {
        expected[14 + U + i] = digest[i];
    }
    assert(offset >= claim_start);
    assert(offset + U + 46 <= tbs_len);
    assert_bytes_at(tbs, offset, expected);
}

fn assert_bytes_at<let M: u32, let N: u32>(buf: [u8; M], offset: u32, pattern: [u8; N]) {
    for i in 0..N {
        assert(buf[offset + i] == pattern[i]);
    }
}

/// Number of occurrences of `pattern` lying fully inside buf[start..end).
fn count_in_range<let M: u32, let N: u32>(
    buf: [u8; M],
    start: u32,
    end: u32,
    pattern: [u8; N],
) -> u32 {
    let mut count = 0;
    for i in 0..(M - N + 1) {
        let mut hit = (i >= start) & (i + N <= end);
        for k in 0..N {
            hit &= buf[i + k] == pattern[k];
        }
        count += hit as u32;
    }
    count
}

fn be16(hi: u8, lo: u8) -> u32 {
    (hi as u32) * 256 + (lo as u32)
}
