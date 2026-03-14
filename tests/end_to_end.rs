#![allow(clippy::unwrap_used, clippy::type_complexity)]
#![cfg(feature = "test-utils")]

use veil::audit;
use veil::crypto::VeilError;
use veil::envelope;
use veil::group;
use veil::stream;
use veil::test_utils::make_user;

// ---- Full lifecycle: keys → group → seal → audit → verify ----

#[test]
fn full_lifecycle_group_envelope_with_audit() {
    // 1. Generate identities
    let (id_a, dh_a, pub_a, sign_a, sign_pub_a) = make_user();
    let (id_b, dh_b, pub_b, _sign_b, _) = make_user();

    // 2. Create group
    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
    let (bundle, _) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
    group::verify_bundle(&bundle, &sign_pub_a).unwrap();

    // 3. Seal group envelope
    let gek_a = group::unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();
    let env = group::seal(b"confidential data", &gek_a, "team", &id_a, &sign_a, None).unwrap();

    // 4. Create audit chain
    let e1 = audit::create_entry("seal", &id_a, None, 1_000, None, &sign_a).unwrap();
    let e2 = audit::create_entry("grant", &id_a, Some(&id_b), 2_000, Some(&e1.entry_hash), &sign_a).unwrap();
    audit::verify_chain(&[e1.clone(), e2.clone()]).unwrap();
    audit::verify_entry(&e1, &sign_pub_a).unwrap();
    audit::verify_entry(&e2, &sign_pub_a).unwrap();

    // 5. Anchor envelope to audit chain
    let anchored = audit::anchor_envelope(&env, &e2);
    audit::verify_anchor(&anchored, &[e1, e2]).unwrap();

    // 6. Verify signature is still valid after anchoring
    envelope::verify(&anchored, &sign_pub_a).unwrap();

    // 7. Both members can still open
    let pt_a = group::open(&anchored, &gek_a).unwrap();
    assert_eq!(&*pt_a, b"confidential data");

    let gek_b = group::unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
    let pt_b = group::open(&anchored, &gek_b).unwrap();
    assert_eq!(&*pt_b, b"confidential data");
}

// ---- Full lifecycle: direct envelope with recipient management ----

#[test]
fn full_lifecycle_direct_envelope_with_audit() {
    let (id_a, dh_a, pub_a, sign_a, sign_pub_a) = make_user();
    let (id_b, dh_b, pub_b, _sign_b, _) = make_user();
    let (id_c, dh_c, pub_c, _sign_c, _) = make_user();

    // 1. Seal for Alice only
    let env = envelope::seal(b"secret", &id_a, &pub_a, &sign_a, &[], None).unwrap();
    envelope::verify(&env, &sign_pub_a).unwrap();

    // 2. Add Bob
    let env = envelope::add_recipient(&env, &id_a, &dh_a, &pub_a, &sign_a, &id_b, &pub_b).unwrap();
    assert_eq!(env.recipients().len(), 2);

    // 3. Add Carol
    let env = envelope::add_recipient(&env, &id_a, &dh_a, &pub_a, &sign_a, &id_c, &pub_c).unwrap();
    assert_eq!(env.recipients().len(), 3);

    // 4. All three can open
    assert_eq!(&*envelope::open(&env, &id_a, &dh_a, &pub_a).unwrap(), b"secret");
    assert_eq!(&*envelope::open(&env, &id_b, &dh_b, &pub_b).unwrap(), b"secret");
    assert_eq!(&*envelope::open(&env, &id_c, &dh_c, &pub_c).unwrap(), b"secret");

    // 5. Remove Bob
    let env = envelope::remove_recipient(&env, &id_a, &sign_a, &id_b).unwrap();
    assert_eq!(env.recipients().len(), 2);
    assert!(envelope::open(&env, &id_b, &dh_b, &pub_b).is_err(),
        "removed recipient must not open");

    // 6. Audit the lifecycle
    let e1 = audit::create_entry("seal", &id_a, None, 1_000, None, &sign_a).unwrap();
    let e2 = audit::create_entry("grant", &id_a, Some(&id_b), 2_000, Some(&e1.entry_hash), &sign_a).unwrap();
    let e3 = audit::create_entry("grant", &id_a, Some(&id_c), 3_000, Some(&e2.entry_hash), &sign_a).unwrap();
    let e4 = audit::create_entry("revoke", &id_a, Some(&id_b), 4_000, Some(&e3.entry_hash), &sign_a).unwrap();
    audit::verify_chain(&[e1, e2, e3, e4.clone()]).unwrap();

    // 7. Anchor to the last audit entry
    let anchored = audit::anchor_envelope(&env, &e4);
    envelope::verify(&anchored, &sign_pub_a).unwrap();
}

// ---- Full lifecycle: streaming with group ----

#[test]
fn full_lifecycle_group_stream() {
    let (id_a, dh_a, pub_a, sign_a, sign_pub_a) = make_user();
    let (id_b, dh_b, pub_b, _sign_b, _) = make_user();

    // 1. Create group
    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
    let (bundle, _) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
    let gek = group::unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();

    // 2. Stream-seal with group
    let meta = serde_json::json!({"filename": "report.pdf"});
    let mut sealer = stream::create_group_sealer(
        &id_a, &sign_a, &gek, "team", Some(meta.clone()), Some(64),
    ).unwrap();
    let data = vec![0xABu8; 200];
    let enc0 = sealer.seal_chunk(&data[..64], false).unwrap();
    let enc1 = sealer.seal_chunk(&data[64..128], false).unwrap();
    let enc2 = sealer.seal_chunk(&data[128..], true).unwrap();
    let header = sealer.header();

    // 3. Verify header
    stream::verify_header(header, &sign_pub_a).unwrap();
    assert_eq!(header.metadata, Some(meta));

    // 4. Member B opens
    let gek_b = group::unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
    let dek = stream::unwrap_group_stream_dek(header, &gek_b).unwrap();
    let mut opener = stream::create_opener(header, dek).unwrap();
    let mut result = Vec::new();
    result.extend_from_slice(&opener.open_chunk(&enc0).unwrap());
    result.extend_from_slice(&opener.open_chunk(&enc1).unwrap());
    result.extend_from_slice(&opener.open_chunk(&enc2).unwrap());
    assert!(opener.is_done());
    assert_eq!(result, data);

    // 5. After member removal, old GEK can't unwrap new streams
    let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
    let (updated, _) = group::remove_member(&bundle, &id_a, &sign_a, &id_b, &remaining).unwrap();
    let new_gek = group::unwrap_gek(&updated, &id_a, &dh_a, &pub_a).unwrap();

    let mut sealer2 = stream::create_group_sealer(
        &id_a, &sign_a, &new_gek, "team", None, None,
    ).unwrap();
    sealer2.seal_chunk(b"post-rotation", true).unwrap();
    let header2 = sealer2.header();

    let result = stream::unwrap_group_stream_dek(header2, &gek_b);
    assert!(matches!(result, Err(VeilError::Crypto(_))),
        "old GEK must not unwrap post-rotation stream");
}
