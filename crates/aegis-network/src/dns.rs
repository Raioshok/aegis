//! DNS-tunneling / DGA heuristics.
//!
//! Data-exfiltration over DNS and domain-generation-algorithm (DGA) C2 domains
//! share statistical fingerprints: long, high-entropy, many-label names whose
//! labels look like encoded data. `tunnel_score` returns a 0.0–1.0 suspicion
//! score from those features; pure and unit-tested.

use aegis_engine::shannon_entropy;

/// Features extracted from a query name.
#[derive(Debug, Clone)]
pub struct DnsFeatures {
    pub length: usize,
    pub label_count: usize,
    pub longest_label: usize,
    pub entropy: f64,
    pub digit_ratio: f64,
}

pub fn features(qname: &str) -> DnsFeatures {
    let name = qname.trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    let longest = labels.iter().map(|l| l.len()).max().unwrap_or(0);
    let digits = name.chars().filter(|c| c.is_ascii_digit()).count();
    let alnum = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count()
        .max(1);
    DnsFeatures {
        length: name.len(),
        label_count: labels.len(),
        longest_label: longest,
        entropy: shannon_entropy(name.as_bytes()),
        digit_ratio: digits as f64 / alnum as f64,
    }
}

/// Suspicion score in 0.0–1.0. Higher = more tunnel/DGA-like.
pub fn tunnel_score(qname: &str) -> f64 {
    let f = features(qname);
    let mut score = 0.0f64;
    // Very long names are unusual for legitimate lookups.
    if f.length > 60 {
        score += 0.3;
    } else if f.length > 40 {
        score += 0.15;
    }
    // A single very long label is the hallmark of encoded payloads.
    if f.longest_label > 40 {
        score += 0.3;
    } else if f.longest_label > 25 {
        score += 0.15;
    }
    // High per-character entropy → base32/hex-encoded data, not words.
    if f.entropy > 4.0 {
        score += 0.25;
    } else if f.entropy > 3.5 {
        score += 0.1;
    }
    // Lots of labels (chunked exfil).
    if f.label_count > 6 {
        score += 0.15;
    }
    // Heavy digit content.
    if f.digit_ratio > 0.4 {
        score += 0.1;
    }
    score.min(1.0)
}

/// Whether a query name crosses the alerting threshold.
pub fn is_suspicious(qname: &str) -> bool {
    tunnel_score(qname) >= 0.6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_domains_score_low() {
        assert!(tunnel_score("google.com") < 0.4);
        assert!(tunnel_score("mail.example.co.uk") < 0.5);
        assert!(!is_suspicious("cdn.jsdelivr.net"));
    }

    #[test]
    fn tunnel_domains_score_high() {
        let exfil = "k7f9a2b8c1d4e6f0a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6.tunnel.evil.example";
        assert!(is_suspicious(exfil), "score={}", tunnel_score(exfil));
        let long_label = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPIFA.exfil.bad.com";
        assert!(tunnel_score(long_label) > 0.5);
    }
}
