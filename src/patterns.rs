use regex::Regex;

#[allow(dead_code)]
pub struct SecretPattern {
    pub name: &'static str,
    pub regex: Regex,
    pub description: &'static str,
}

pub struct PatternSet {
    pub patterns: Vec<SecretPattern>,
}

impl PatternSet {
    pub fn default_patterns() -> Self {
        let patterns = vec![
            SecretPattern {
                name: "evm_private_key",
                regex: Regex::new(
                    r#"(?i)(?:private_?key|privkey|secret_?key)['"]?\s*[:=]\s*['"]?(0x[0-9a-fA-F]{64})['"]?"#,
                )
                .unwrap(),
                description: "EVM/Ethereum private key (0x + 64 hex chars)",
            },
            SecretPattern {
                name: "hex_private_key_raw",
                regex: Regex::new(
                    r#"(?i)(?:private_?key|priv_?key)['"]?\s*[:=]\s*['"]?([0-9a-fA-F]{64})['"]?"#,
                )
                .unwrap(),
                description: "Raw hex private key (64 hex chars)",
            },
            SecretPattern {
                name: "aws_access_key",
                regex: Regex::new(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}").unwrap(),
                description: "AWS access key ID",
            },
            SecretPattern {
                name: "aws_secret_key",
                regex: Regex::new(
                    r#"(?i)(?:aws_?secret_?access_?key|aws_?secret_?key)['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
                )
                .unwrap(),
                description: "AWS secret access key",
            },
            SecretPattern {
                name: "generic_api_key",
                regex: Regex::new(
                    r#"(?i)(?:api_?key|api_?secret|apikey)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
                )
                .unwrap(),
                description: "Generic API key assignment",
            },
            SecretPattern {
                name: "generic_secret",
                regex: Regex::new(
                    r#"(?i)(?:secret|password|passwd|token)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]"#,
                )
                .unwrap(),
                description: "Generic secret/password/token assignment",
            },
            SecretPattern {
                name: "pem_private_key",
                regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
                    .unwrap(),
                description: "PEM-encoded private key header",
            },
        ];

        Self { patterns }
    }

    /// Return only private key patterns.
    pub fn private_keys_only() -> Self {
        let all = Self::default_patterns();
        let patterns = all
            .patterns
            .into_iter()
            .filter(|p| is_private_key_pattern(p.name))
            .collect();
        Self { patterns }
    }

    /// Run all patterns against text, returning (pattern_name, matched_text) pairs.
    pub fn scan_text<'a>(&'a self, text: &str) -> Vec<(&'a str, String)> {
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            for cap in pattern.regex.captures_iter(text) {
                let matched = cap
                    .get(1)
                    .unwrap_or_else(|| cap.get(0).unwrap())
                    .as_str()
                    .to_string();
                matches.push((pattern.name, matched));
            }
        }
        matches
    }
}

fn is_private_key_pattern(name: &str) -> bool {
    matches!(
        name,
        "evm_private_key" | "hex_private_key_raw" | "pem_private_key"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_private_key() {
        let ps = PatternSet::default_patterns();
        let text = r#"privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'"#;
        let results = ps.scan_text(text);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "evm_private_key");
    }

    #[test]
    fn test_aws_access_key() {
        let ps = PatternSet::default_patterns();
        let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let results = ps.scan_text(text);
        assert!(results.iter().any(|(name, _)| *name == "aws_access_key"));
    }

    #[test]
    fn test_pem_key() {
        let ps = PatternSet::default_patterns();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...";
        let results = ps.scan_text(text);
        assert!(results.iter().any(|(name, _)| *name == "pem_private_key"));
    }

    #[test]
    fn test_evm_private_key_camelcase_single_quotes() {
        let ps = PatternSet::default_patterns();
        // Exact format from Jupyter notebook cell output
        let text = r#"'privateKey': '0x3b0640259cb0441f71acf8ca43593bb9cb2c979d07d0b0afb7421507caa81d76'"#;
        let results = ps.scan_text(text);
        assert!(
            results.iter().any(|(name, _)| *name == "evm_private_key"),
            "Should match camelCase privateKey with single quotes, got: {:?}",
            results
        );
    }

    #[test]
    fn test_no_false_positive_on_plain_hex() {
        let ps = PatternSet::default_patterns();
        // Plain hex string without assignment context should not match evm_private_key
        let text = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let results = ps.scan_text(text);
        assert!(
            !results.iter().any(|(name, _)| *name == "evm_private_key"),
            "Should not match bare hex without assignment context"
        );
    }
}
