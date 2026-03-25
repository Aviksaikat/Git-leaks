use k256::SecretKey;

/// Check if a hex string (with or without 0x prefix) is a valid secp256k1 private key.
///
/// A valid key must be:
/// - Exactly 64 hex characters (32 bytes) after stripping optional 0x prefix
/// - Non-zero
/// - Less than the secp256k1 curve order n
pub fn is_valid_secp256k1_key(hex_str: &str) -> bool {
    let hex = hex_str.strip_prefix("0x").or_else(|| hex_str.strip_prefix("0X")).unwrap_or(hex_str);

    if hex.len() != 64 {
        return false;
    }

    let bytes = match hex_to_bytes(hex) {
        Some(b) => b,
        None => return false,
    };

    // k256::SecretKey::from_slice validates: non-zero AND < curve order
    SecretKey::from_slice(&bytes).is_ok()
}

fn hex_to_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_hardhat_key() {
        // Hardhat account #0 — known valid secp256k1 key
        assert!(is_valid_secp256k1_key(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        ));
    }

    #[test]
    fn test_valid_key_no_prefix() {
        assert!(is_valid_secp256k1_key(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        ));
    }

    #[test]
    fn test_leaked_key() {
        assert!(is_valid_secp256k1_key(
            "0x3b0640259cb0441f71acf8ca43593bb9cb2c979d07d0b0afb7421507caa81d76"
        ));
    }

    #[test]
    fn test_zero_key_invalid() {
        assert!(!is_valid_secp256k1_key(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_curve_order_invalid() {
        // secp256k1 curve order n — must be strictly less than this
        assert!(!is_valid_secp256k1_key(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        ));
    }

    #[test]
    fn test_above_curve_order_invalid() {
        assert!(!is_valid_secp256k1_key(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142"
        ));
    }

    #[test]
    fn test_short_hex_invalid() {
        assert!(!is_valid_secp256k1_key("0xdeadbeef"));
    }

    #[test]
    fn test_non_hex_invalid() {
        assert!(!is_valid_secp256k1_key(
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_max_valid_key() {
        // n - 1 should be valid
        assert!(is_valid_secp256k1_key(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
        ));
    }
}
