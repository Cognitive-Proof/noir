// Selective disclosure over a C2PA manifest:
//
//   "The image whose SHA-256 is `asset_hash` carries a C2PA claim signed by
//    `signer_pubkey`, and that claim's c2pa.actions assertion declares no
//    AI-generated digital source type."
//
// Everything else in the manifest (EXIF/GPS, author, title, thumbnail,
// certificate chain, the actions themselves) stays private.
use sha256::sha256_var;

global MAX_TBS: u32 = 2048;
global MAX_ACTIONS: u32 = 512;
global MAX_HASH_DATA: u32 = 256;

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
    signer_pubkey_x: pub [u8; 32],
    signer_pubkey_y: pub [u8; 32],
    asset_hash: pub [u8; 32],
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
) {
    // 1. The claim signature: ES256 over the COSE Sig_structure
    //    ["Signature1", protected, h'', claim]
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

    // 3. The actions assertion declares no AI digital source type.
    assert(count_in_range(actions, 0, actions_len, AI_TRAINED) == 0);
    assert(count_in_range(actions, 0, actions_len, AI_ALGORITHMIC) == 0);
    assert(count_in_range(actions, 0, actions_len, AI_COMPOSITE_SYNTHETIC) == 0);

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
