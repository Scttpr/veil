#![allow(clippy::unwrap_used, clippy::type_complexity)]
#![cfg(feature = "test-utils")]

use veil::crypto::VeilError;
use veil::group;
use veil::stream;
use veil::test_utils::make_user;

// ---- Group stream: create, seal chunks, open ----

#[test]
fn group_stream_seal_open_roundtrip() {
    let (id_a, _dh_a, pub_a, sign_a, sign_pub_a) = make_user();
    let (id_b, _dh_b, pub_b, _sign_b, _) = make_user();

    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a), (&id_b, &pub_b)];
    let (_bundle, gek) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();

    let mut sealer = stream::create_group_sealer(
        &id_a, &sign_a, &gek, "team", None, Some(32),
    ).unwrap();
    let enc0 = sealer.seal_chunk(b"hello ", false).unwrap();
    let enc1 = sealer.seal_chunk(b"world", true).unwrap();

    let header = sealer.header();

    // Verify header signature
    stream::verify_header(header, &sign_pub_a).unwrap();

    // Member B opens using GEK
    let dek = stream::unwrap_group_stream_dek(header, &gek).unwrap();
    let mut opener = stream::create_opener(header, dek).unwrap();
    assert_eq!(&*opener.open_chunk(&enc0).unwrap(), b"hello ");
    assert_eq!(&*opener.open_chunk(&enc1).unwrap(), b"world");
    assert!(opener.is_done());
}

// ---- Wrong GEK cannot unwrap group stream ----

#[test]
fn group_stream_wrong_gek_fails() {
    let (id_a, _dh_a, pub_a, sign_a, _) = make_user();

    let members: Vec<(&str, &[u8; 32])> = vec![(&id_a, &pub_a)];
    let (_bundle, gek) = group::create_bundle("team", 1, &id_a, &sign_a, &members).unwrap();

    let mut sealer = stream::create_group_sealer(
        &id_a, &sign_a, &gek, "team", None, None,
    ).unwrap();
    sealer.seal_chunk(b"data", true).unwrap();
    let header = sealer.header();

    let wrong_gek = [0xABu8; 32];
    let result = stream::unwrap_group_stream_dek(header, &wrong_gek);
    assert!(matches!(result, Err(VeilError::Crypto(_))),
        "wrong GEK must fail to unwrap group stream DEK");
}

