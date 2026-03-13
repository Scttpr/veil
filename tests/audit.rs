#![allow(clippy::unwrap_used, clippy::type_complexity)]
#![cfg(feature = "test-utils")]

use veil::audit;
use veil::crypto::{self, VeilError};
use veil::envelope;
use veil::test_utils::make_user;

// ---- Anchor (integration: audit + envelope) ----

#[test]
fn test_anchor_envelope() {
    let (id, _, public, sign_sec, _) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
    let entry = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();

    let anchored = audit::anchor_envelope(&env, &entry);
    assert_eq!(anchored.audit_hash.as_deref(), Some(entry.entry_hash.as_str()));
}

#[test]
fn test_anchor_matches_last_entry() {
    let (id, _, public, sign_sec, _) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
    let e1 = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
    let e2 = audit::create_entry("grant", &id, Some("bob"), 2_000, Some(&e1.entry_hash), &sign_sec).unwrap();

    // Anchor to the last entry
    let anchored = audit::anchor_envelope(&env, &e2);
    assert!(audit::verify_anchor(&anchored, &[e1.clone(), e2]).is_ok());

    // Anchor to e1 but provide both entries → chain head = e2, anchor = e1 → mismatch
    let bad_anchor = audit::anchor_envelope(&env, &e1);
    let entries_both = vec![e1.clone(), audit::create_entry("grant", &id, Some("bob"), 2_000, Some(&e1.entry_hash), &sign_sec).unwrap()];
    assert!(matches!(audit::verify_anchor(&bad_anchor, &entries_both), Err(VeilError::Validation(_))), "mismatched anchor must fail verification");
}

// ---- audit_hash not in signature ----

#[test]
fn test_audit_hash_not_in_signature() {
    let (id, _, public, sign_sec, sign_pub) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();

    // Verify signature before anchoring
    assert!(envelope::verify(&env, &sign_pub).is_ok());

    // Anchor
    let entry = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
    let anchored = audit::anchor_envelope(&env, &entry);

    // Signature should still be valid
    assert!(envelope::verify(&anchored, &sign_pub).is_ok());
}

// ---- audit_hash omitted when None ----

#[test]
fn test_audit_hash_omitted_without_audit() {
    let (id, _, public, sign_sec, _) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
    assert!(env.audit_hash.is_none());

    let json = serde_json::to_string(&env).unwrap();
    assert!(!json.contains("\"audit_hash\""), "audit_hash must be omitted from JSON when None");
}

// ---- Prove audit_hash is independent of signature ----

#[test]
fn test_audit_hash_mutation_does_not_break_signature() {
    let (id, _, public, sign_sec, sign_pub) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();

    // Anchor to an audit entry
    let entry = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
    let anchored = audit::anchor_envelope(&env, &entry);
    assert!(envelope::verify(&anchored, &sign_pub).is_ok());

    // Tamper with audit_hash — signature must still be valid
    // (proves audit_hash is NOT signed)
    let mut tampered = anchored.clone();
    tampered.audit_hash = Some("totally-fake-hash".to_string());
    assert!(envelope::verify(&tampered, &sign_pub).is_ok(),
        "modifying audit_hash must not invalidate the envelope signature");

    // Remove audit_hash — signature must still be valid
    let mut removed = anchored;
    removed.audit_hash = None;
    assert!(envelope::verify(&removed, &sign_pub).is_ok(),
        "removing audit_hash must not invalidate the envelope signature");
}

// ---- Audit chain reorder detection ----

#[test]
fn test_audit_chain_reorder_detected() {
    let (id, _, _, sign_sec, _) = make_user();
    let e1 = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
    let e2 = audit::create_entry("grant", &id, Some("bob"), 2_000, Some(&e1.entry_hash), &sign_sec).unwrap();

    // Correct order works
    assert!(audit::verify_chain(&[e1.clone(), e2.clone()]).is_ok());

    // Reversed order must fail (e2's prev_hash points to e1, but e2 comes first
    // so genesis check fails on e2)
    assert!(matches!(
        audit::verify_chain(&[e2, e1]),
        Err(VeilError::Validation(_))
    ), "reordered chain must be rejected");
}

// ---- Duplicate entry in chain ----

#[test]
fn test_audit_chain_duplicate_entry() {
    let (id, _, _, sign_sec, _) = make_user();
    let e1 = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();

    // Same entry twice: e1's prev_hash should not match e1's entry_hash
    let result = audit::verify_chain(&[e1.clone(), e1]);
    assert!(matches!(result, Err(VeilError::Validation(_))),
        "chain with duplicate entries must be rejected");
}

// ---- Multiple signers in chain ----

#[test]
fn test_audit_chain_multiple_signers() {
    let (id_a, _, _, sign_a, sign_pub_a) = make_user();
    let (id_b, _, _, sign_b, sign_pub_b) = make_user();

    // Alice creates the genesis entry
    let e1 = audit::create_entry("seal", &id_a, None, 1_000, None, &sign_a).unwrap();
    // Bob adds a grant entry
    let e2 = audit::create_entry("grant", &id_b, Some("carol"), 2_000, Some(&e1.entry_hash), &sign_b).unwrap();
    // Alice adds a revoke entry
    let e3 = audit::create_entry("revoke", &id_a, Some("carol"), 3_000, Some(&e2.entry_hash), &sign_a).unwrap();

    // Chain verification (linkage only) should pass
    let head = audit::verify_chain(&[e1.clone(), e2.clone(), e3.clone()]).unwrap();
    assert_eq!(head, e3.entry_hash);

    // Individual entry verification with correct keys
    assert!(audit::verify_entry(&e1, &sign_pub_a).is_ok());
    assert!(audit::verify_entry(&e2, &sign_pub_b).is_ok());
    assert!(audit::verify_entry(&e3, &sign_pub_a).is_ok());

    // Cross-verification must fail
    assert!(audit::verify_entry(&e1, &sign_pub_b).is_err(),
        "Alice's entry must not verify with Bob's key");
    assert!(audit::verify_entry(&e2, &sign_pub_a).is_err(),
        "Bob's entry must not verify with Alice's key");
}

// ---- Anchor without audit_hash ----

#[test]
fn test_verify_anchor_without_audit_hash_fails() {
    let (id, _, public, sign_sec, _) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
    let e1 = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();

    // Envelope has no audit_hash
    let result = audit::verify_anchor(&env, &[e1]);
    assert!(matches!(result, Err(VeilError::Validation(_))),
        "envelope without audit_hash must fail anchor verification");
}

// ---- Anchor with empty chain ----

#[test]
fn test_verify_anchor_empty_chain_fails() {
    let (id, _, public, sign_sec, _) = make_user();
    let env = envelope::seal(b"data", &id, &public, &sign_sec, &[], None).unwrap();
    let e1 = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
    let anchored = audit::anchor_envelope(&env, &e1);

    let result = audit::verify_anchor(&anchored, &[]);
    assert!(result.is_err(), "empty chain must fail anchor verification");
}

// ---- Tampered entry hash in chain detected ----

#[test]
fn test_audit_chain_tampered_entry_hash() {
    let (id, _, _, sign_sec, _) = make_user();
    let e1 = audit::create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
    let mut e2 = audit::create_entry("grant", &id, Some("bob"), 2_000, Some(&e1.entry_hash), &sign_sec).unwrap();

    // Tamper with e2's entry_hash
    e2.entry_hash = crypto::to_base64(&[0xFFu8; 32]);

    let result = audit::verify_chain(&[e1, e2]);
    assert!(matches!(result, Err(VeilError::Validation(_))),
        "tampered entry_hash must be detected by chain verification");
}
