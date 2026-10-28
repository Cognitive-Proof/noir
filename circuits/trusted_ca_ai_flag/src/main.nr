// Selective disclosure over a C2PA manifest, one proof per image:
//
//   "The image whose SHA-256 is `asset_hash` carries a C2PA claim signed by a
//    certificate issued by the CA `ca_pubkey`, and `has_ai` says whether that
//    claim's c2pa.actions assertion declares an AI-generated source type."
//
// The signer's identity, EXIF/GPS, author, title, thumbnail and the actions
// themselves stay private; only the one-bit AI verdict is disclosed.
use sha256::sha256_var;

global MAX_TBS: u32 = 2048;
global MAX_ACTIONS: u32 = 512;
global MAX_HASH_DATA: u32 = 256;
global MAX_TBS_CERT: u32 = 1024;

// SubjectPublicKeyInfo for an uncompressed P-256 key, up to the 0x04 point tag:
// SEQ { SEQ { id-ecPublicKey, prime256v1 }, BIT STRING 0x00 0x04 ... }
global P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

// COSE Sig_structure prefix: array(4), tstr(10) "Signature1"
global SIG1_PREFIX: [u8; 12] = [0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31];
// Offset of the protected-header bytes / claim bytes inside the Sig_structure
global PROTECTED_START: u32 = 15;
global CLAIM_HEADER_LEN: u32 = 4; // 0x40 (empty aad) + 0x59 len16 (claim)

global ACTIONS_URL: [u8; 42] = "self#jumbf=c2pa.assertions/c2pa.actions.v2".as_bytes();
global HASH_DATA_URL: [u8; 41] = "self#jumbf=c2pa.assertions/c2pa.hash.data".as_bytes();
// Every actions assertion label (c2pa.actions, c2pa.actions.v2, c2pa.actions__1, ...)
global ACTIONS_PREFIX: [u8; 28] = "c2pa.assertions/c2pa.actions".as_bytes();

// IPTC digitalSourceType values treated as AI / synthetic generation.
// "rainedAlgorithmicMedia" covers trainedAlgorithmicMedia and
// compositeWithTrainedAlgorithmicMedia.
global AI_TRAINED: [u8; 22] = "rainedAlgorithmicMedia".as_bytes();
global AI_ALGORITHMIC: [u8; 16] = "algorithmicMedia".as_bytes();
global AI_COMPOSITE_SYNTHETIC: [u8; 18] = "compositeSynthetic".as_bytes();

fn main(
    ca_pubkey_x: pub [u8; 32],
    ca_pubkey_y: pub [u8; 32],
    asset_hash: pub [u8; 32],
    leaf_tbs_cert: [u8; MAX_TBS_CERT],
    leaf_tbs_cert_len: u32,
    leaf_cert_sig: [u8; 64],
    leaf_spki_offset: u32,
    signature: [u8; 64],
    tbs: [u8; MAX_TBS],
    tbs_len: u32,
    protected_len: u32,
    actions: [u8; MAX_ACTIONS],
    actions_len: u32,
    actions_ref_offset: u32,
    hash_data: [u8; MAX_HASH_DATA],
    hash_data_len: u32,
    hash_data_ref_offset: u32,
    asset_hash_offset: u32,
) -> pub bool {
    // 0. The trusted CA issued the signer's certificate, and that certificate
    //    holds the P-256 key (x, y) that signed the claim.
    assert(leaf_tbs_cert_len <= MAX_TBS_CERT);
    let cert_hash = sha256_var(leaf_tbs_cert, leaf_tbs_cert_len);
    assert(std::ecdsa_secp256r1::verify_signature(ca_pubkey_x, ca_pubkey_y, leaf_cert_sig, cert_hash));
    assert(leaf_spki_offset + 27 + 64 <= leaf_tbs_cert_len);
    assert_bytes_at(leaf_tbs_cert, leaf_spki_offset, P256_SPKI_PREFIX);
    let mut signer_pubkey_x = [0; 32];
    let mut signer_pubkey_y = [0; 32];
    for i in 0..32 {
        signer_pubkey_x[i] = leaf_tbs_cert[leaf_spki_offset + 27 + i];
        signer_pubkey_y[i] = leaf_tbs_cert[leaf_spki_offset + 59 + i];
    }

    // 1. The claim signature: ES256 over the COSE Sig_structure
    //    ["Signature1", protected, h'', claim], under the certified key.
    let claim_start = check_sig_structure(tbs, tbs_len, protected_len);
    let tbs_hash = sha256_var(tbs, tbs_len);
    assert(std::ecdsa_secp256r1::verify_signature(
        signer_pubkey_x,
        signer_pubkey_y,
        signature,
        tbs_hash,
    ));

    // 2. The signed claim references the actions assertion by hash, and it is
    //    the only actions assertion in the claim (no cherry-picking).
    let actions_hash = sha256_var(actions, actions_len);
    assert_hashed_uri(tbs, tbs_len, claim_start, actions_ref_offset, ACTIONS_URL, actions_hash);
    assert(count_in_range(tbs, claim_start, tbs_len, ACTIONS_PREFIX) == 1);

    // 3. Verdict: does the actions assertion declare an AI digital source type?
    let ai_mentions = count_in_range(actions, 0, actions_len, AI_TRAINED)
        + count_in_range(actions, 0, actions_len, AI_ALGORITHMIC)
        + count_in_range(actions, 0, actions_len, AI_COMPOSITE_SYNTHETIC);

    // 4. Bind to the published pixels: the signed c2pa.hash.data assertion
    //    carries `asset_hash`, which the verifier recomputes from the image.
    let hash_data_hash = sha256_var(hash_data, hash_data_len);
    assert_hashed_uri(
        tbs,
        tbs_len,
        claim_start,
        hash_data_ref_offset,
        HASH_DATA_URL,
        hash_data_hash,
    );
    // "hash": bstr .size 32
    let mut asset_field = [0; 39];
    let key = [0x64, 0x68, 0x61, 0x73, 0x68, 0x58, 0x20];
    for i in 0..7 {
        asset_field[i] = key[i];
    }
    for i in 0..32 {
        asset_field[7 + i] = asset_hash[i];
    }
    assert(asset_hash_offset + 39 <= hash_data_len);
    assert_bytes_at(hash_data, asset_hash_offset, asset_field);

    ai_mentions != 0
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
