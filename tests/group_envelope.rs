#![allow(clippy::unwrap_used, clippy::type_complexity)]
#![cfg(feature = "test-utils")]

use veil::crypto::VeilError;
use veil::envelope;
use veil::group;
use veil::test_utils::make_user;

// ---- Group envelope: seal, verify, open ----

#[test]
fn group_seal_verify_open() {
    let (id_a, dh_a, pub_a, sign_a, sign_pub_a) = make_user();
    let (id_b, dh_b, pub_b, _sign_b, _) = make_user();

    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
    let (bundle, _) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
    let gek = group::unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();

    let env = group::seal(b"group secret", &gek, "team", &id_a, &sign_a, None).unwrap();

    // Signature verification via envelope::verify
    envelope::verify(&env, &sign_pub_a).unwrap();

    // Both members can open
    let pt_a = group::open(&env, &gek).unwrap();
    assert_eq!(&*pt_a, b"group secret");

    let gek_b = group::unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
    let pt_b = group::open(&env, &gek_b).unwrap();
    assert_eq!(&*pt_b, b"group secret");
}

// ---- Non-member cannot open group envelope ----

#[test]
fn group_non_member_cannot_open() {
    let (id_a, dh_a, pub_a, sign_a, _) = make_user();
    let (id_b, _dh_b, pub_b, _sign_b, _) = make_user();

    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
    let (bundle, _) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
    let gek = group::unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();

    let env = group::seal(b"secret", &gek, "team", &id_a, &sign_a, None).unwrap();

    // A random GEK (non-member) must fail
    let fake_gek = [0xFFu8; 32];
    let result = group::open(&env, &fake_gek);
    assert!(matches!(result, Err(VeilError::Crypto(_))),
        "non-member GEK must not open group envelope");
}

// ---- Group envelope signature covers group_id (cross-module) ----

#[test]
fn group_envelope_verify_wrong_key_fails() {
    let (id_a, dh_a, pub_a, sign_a, _) = make_user();
    let (_, _, _, _, wrong_pub) = make_user();

    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
    let (bundle, _) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();
    let gek = group::unwrap_gek(&bundle, &id_a, &dh_a, &pub_a).unwrap();

    let env = group::seal(b"data", &gek, "team", &id_a, &sign_a, None).unwrap();

    assert!(envelope::verify(&env, &wrong_pub).is_err(),
        "group envelope must not verify with wrong key");
}

// ---- Removed member cannot open post-rotation envelope ----

#[test]
fn group_rotation_revokes_access() {
    let (id_a, dh_a, pub_a, sign_a, _) = make_user();
    let (id_b, dh_b, pub_b, _sign_b, _) = make_user();

    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
    let (bundle, _) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();

    // Bob can open before removal
    let old_gek = group::unwrap_gek(&bundle, &id_b, &dh_b, &pub_b).unwrap();
    let env1 = group::seal(b"before", &old_gek, "team", &id_a, &sign_a, None).unwrap();
    assert_eq!(&*group::open(&env1, &old_gek).unwrap(), b"before");

    // Remove Bob → GEK rotates
    let remaining: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
    let (updated, _) = group::remove_member(&bundle, &id_a, &sign_a, &id_b, &remaining).unwrap();
    let new_gek = group::unwrap_gek(&updated, &id_a, &dh_a, &pub_a).unwrap();

    // New envelope with rotated GEK
    let env2 = group::seal(b"after", &new_gek, "team", &id_a, &sign_a, None).unwrap();

    // Bob's old GEK cannot open the new envelope
    assert!(group::open(&env2, &old_gek).is_err(),
        "removed member's old GEK must not open post-rotation envelope");

    // Bob cannot unwrap the new GEK
    assert!(group::unwrap_gek(&updated, &id_b, &dh_b, &pub_b).is_err(),
        "removed member must not unwrap rotated GEK");
}
