// Test-only decoy: same public inputs and output as trusted_ca_ai_flag, but
// proves nothing and always reports has_ai = false. A verifier that trusted
// the key shipped with a proof would accept its proofs.
fn main(_ca_pubkey_x: pub [u8; 32], _ca_pubkey_y: pub [u8; 32], _asset_hash: pub [u8; 32]) -> pub bool {
    false
}
