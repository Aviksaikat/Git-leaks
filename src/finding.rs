use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct Finding {
    pub commit_hash: String,
    pub commit_message: String,
    pub commit_date: String,
    pub file_path: String,
    pub pattern_name: String,
    pub matched_text: String,
    /// Whether the matched text was cryptographically verified as a valid secp256k1 private key.
    pub validated_evm_key: bool,
}

/// Deduplicate findings: keep the earliest commit for each unique secret value.
/// Old entries are zeroized on drop to clear secrets from memory.
pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashMap<String, Finding> = HashMap::new();

    for finding in findings {
        let key = finding.matched_text.clone();
        seen.entry(key)
            .and_modify(|existing| {
                // Keep the one with the earlier date
                if finding.commit_date < existing.commit_date {
                    *existing = finding.clone();
                }
            })
            .or_insert(finding);
    }

    let mut results: Vec<Finding> = seen.into_values().collect();
    results.sort_by(|a, b| a.commit_date.cmp(&b.commit_date));
    results
}
