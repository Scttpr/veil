
================================================================================

                        __      __  ______  __  __
                       /\ \    / / /\  ___\/\ \/\ \
                       \ \ \  / /  \ \  __\\ \ \ \ \___
                        \ \_\/ /    \ \_____\ \_\ \_____\
                         \/_/\/      \/_____/\/_/\/_____/

                    End-to-end encryption for the web.
                    Zero-knowledge server. Pure WASM.
                    Architecture ready for post-quantum migration.

================================================================================


WHAT IS VEIL?
-------------

Veil is a Rust-based end-to-end encryption SDK that compiles to WebAssembly.
It provides envelope encryption with multi-recipient access control, allowing
any website to store and share encrypted data without the server ever seeing
plaintext.

Drop it into your existing web application. The server only stores and relays
opaque data. All cryptographic operations happen client-side, inside the
browser, inside the WASM sandbox.


HOW IT WORKS
------------

Veil uses envelope encryption with ECIES (Elliptic Curve Integrated Encryption
Scheme) for per-recipient key wrapping, and Ed25519 signatures for sender
authentication.

1. SEAL

   When a user encrypts data:

     a. A random 256-bit Data Encryption Key (DEK) is generated.
     b. The data is encrypted with the DEK using AES-256-GCM.
     c. For each authorized recipient (including the sealer), the DEK is
        wrapped using ECIES:

            i.   Generate a fresh ephemeral X25519 key pair.
            ii.  DH(ephemeral_secret, recipient_public) -> shared secret.
            iii. HKDF-SHA256(shared_secret,
                     info="veil-wrap" || eph_public || recipient_public)
                     -> wrapping key.
            iv.  AES-256-GCM(wrapping_key, DEK, ad=recipient_public)
                 -> encrypted DEK.

     d. The envelope is signed with the sealer's Ed25519 key. The signature
        covers: "veil-sig-v1" || version(1) || has_signer(1) ||
        [signer_id_len(4 BE) || signer_id] || ciphertext_len(4 BE) ||
        ciphertext || has_metadata(1) || [metadata_len(4 BE) || metadata] ||
        access_type(1) || access_data (recipients or group info).
        All variable-length fields are length-prefixed (4 bytes, big-endian).
        The recipient list IS signed, so adding or removing recipients
        requires re-signing the envelope.

     e. The result is an Envelope: the ciphertext, per-recipient wrapped
        DEKs, optional metadata, and an Ed25519 signature.

2. OPEN

   When a recipient decrypts an envelope:

     a. Find the WrappedKey matching our user ID.
     b. DH(our_secret, ephemeral_public) -> same shared secret.
     c. Derive the same wrapping key via HKDF.
     d. Unwrap the DEK.
     e. Decrypt the ciphertext with the DEK.

   open() verifies the signature before decrypting. Use openUnverified()
   to skip verification (e.g. offline/cached envelopes).

3. VERIFY

   Verify who sealed an envelope:

     a. Fetch the signer's Ed25519 public key from the server.
     b. TOFU-verify the signing key (same pattern as DH key pinning).
     c. Reconstruct the signed payload and verify the Ed25519 signature.

4. GRANT ACCESS

   To add a new recipient to an existing envelope:

     a. Unwrap the DEK (caller must be an existing recipient).
     b. Wrap the DEK for the new recipient's public key.
     c. Append to the envelope's recipient list.
     d. Re-sign the envelope with the caller's Ed25519 key.

   The data is never re-encrypted. Only the DEK is wrapped again.

5. REVOKE ACCESS

   Soft revocation: remove a recipient's wrapped key from the envelope.
   The removed user cannot unwrap the DEK from the updated envelope,
   but if they previously cached the DEK, they could still decrypt.

   Hard revocation: call reseal() to generate a new DEK, re-encrypt the
   data, and re-wrap for remaining recipients. Previously cached DEKs
   become useless. The new envelope is signed by the resealer.

6. GROUP KEYS

   For recurring groups, wrapping the DEK per-member on every seal is
   redundant. Group keys add a shared layer:

     a. Create a group: generate a random 256-bit Group Encryption Key (GEK).
     b. Wrap the GEK per-member using the same ECIES scheme as DEK wrapping.
     c. Store the signed GroupKeyBundle on the server.

   When sealing for a group:

     a. Fetch the group's bundle. Unwrap the GEK.
     b. Generate a random DEK and encrypt the data (AES-256-GCM).
     c. Wrap the DEK with the GEK (AES-256-GCM, AD = "veil-group-dek:" + groupId).
     d. Sign the envelope (group_id is included in the signed payload).

   When opening a group envelope:

     a. Fetch the group's bundle. Unwrap the GEK.
     b. Unwrap the DEK using the GEK. Decrypt the data.

   Member changes:
     - addGroupMember: wrap the existing GEK for the new member. Same epoch.
     - removeGroupMember: generate a NEW GEK (epoch + 1), wrap for remaining
       members. The removed member's old GEK cannot decrypt new envelopes.

   Key hierarchy: Data -> DEK (AES-GCM) -> GEK (AES-GCM) -> per-member ECIES.

7. STREAMING ENCRYPTION

   For large data (files, attachments), streaming encryption avoids loading
   everything into memory. Data is split into fixed-size chunks (default
   64 KiB), each encrypted independently with AES-256-GCM.

   Seal a stream:

     a. Generate a random DEK and an 8-byte random nonce prefix.
     b. Wrap the DEK for each recipient (or with the GEK for group streams).
     c. Build and sign the StreamHeader (JSON).
     d. For each chunk:
          i.   Construct nonce: nonce_prefix(8) || chunk_index(4 BE).
          ii.  Construct AD: "veil-stream" || chunk_index(4 BE) || is_final(1).
          iii. Encrypt with AES-256-GCM using the constructed nonce and AD.
          iv.  Output: is_final(1 byte) || ciphertext || tag(16 bytes).

   Open a stream:

     a. Parse the StreamHeader. Unwrap the DEK.
     b. For each encrypted chunk:
          i.   Read the is_final flag (first byte).
          ii.  Reconstruct nonce and AD from chunk_index.
          iii. Decrypt the chunk.
          iv.  If is_final, mark stream as done.

   Security:
     - Per-chunk authentication prevents reordering (nonce includes index).
     - The is_final flag in AD prevents truncation (removing the last chunk).
     - Each stream uses a unique random nonce prefix.
     - Overhead: 17 bytes per chunk (1 flag + 16 tag). No per-chunk nonce.

8. WHAT THE SERVER SEES

    The server sees:
      - User public keys (DH + signing, safe by design)
      - Encrypted envelopes (unreadable without the recipient's private key)
      - Optional unencrypted metadata (sender ID, timestamps, etc.)

    The server never sees:
      - Private keys
      - Data Encryption Keys
      - Plaintext

9. AUTO-GROUP (TRANSPARENT GROUP KEYS)

   For common messaging patterns (e.g. a DM between two users), manually
   creating and managing groups is tedious. Auto-group provides transparent
   group key management:

     a. autoSeal(plaintext, recipientIds) computes a deterministic group ID
        from the sorted, deduplicated participant list:
        SHA-256("veil-auto-group-v1" || "\n" || sorted_ids.join("\n")) -> "auto:<base64>"

     b. If the auto-group already exists, the existing GEK is used.
        If not, a new group is created automatically.

     c. autoOpen(envelopeJson) transparently dispatches: if the envelope
        has a group_id, it opens via groupOpen; otherwise via direct open.

   Auto-groups reduce per-message overhead for recurring conversations.
   The group ID is deterministic, so all participants compute the same ID.

10. KEY DIRECTORY AND CACHING

   The key directory centralizes public key management and prepares for
   post-quantum key sizes (ML-KEM-768 public keys are 1,184 bytes vs
   32 bytes for X25519).

     a. PublicKeyBundle groups a user's public keys (currently X25519 + Ed25519).
        The struct is designed to be extended with PQ key fields (e.g. kem_public)
        without breaking the API.

     b. KeyCache provides in-memory caching of public key bundles. When a
        recipient's keys are needed, the cache is checked first. Cache misses
        trigger a server fetch. Keys are invalidated on trustKey() calls.

     c. GekCache caches unwrapped Group Encryption Keys keyed by (group_id, epoch).
        This avoids redundant ECIES unwrapping on every group operation. Entries
        are automatically rejected if the epoch doesn't match (stale after rotation).

     d. TOFU (Trust-On-First-Use) verification is centralized in the key directory.
        On first contact, both DH and signing keys are pinned in localStorage.
        Subsequent fetches verify against pins. trustKey() clears pins and cache.


PROJECT STRUCTURE
-----------------

    src/
    +-- lib.rs              Module declarations and re-exports
    +-- constants.rs        Domain-separation strings and protocol constants
    +-- crypto.rs           Low-level primitives (X25519, AES-GCM, HKDF, Ed25519)
    +-- keys.rs             Identity key pairs (X25519 + Ed25519)
    +-- envelope.rs         Envelope encryption (seal, open, verify, grant, revoke, reseal)
    +-- audit.rs            Audit log (hash-chain entries, signatures, anchoring)
    +-- group.rs            Group keys (GEK bundles, group seal/open, GEK cache)
    +-- stream.rs           Streaming encryption (chunked AES-GCM, STREAM construction)
    +-- key_directory.rs    Key directory (PublicKeyBundle, KeyCache, TOFU pinning)
    +-- storage.rs          localStorage persistence + at-rest encryption
    +-- webcrypto_shim.rs   WebCrypto + IndexedDB interop (inline JS shim)
    +-- test_utils.rs       Shared test helpers (make_user, etc.)
    +-- client/
        +-- mod.rs          VeilClient struct and re-exports
        +-- direct.rs       Direct envelope operations (seal, open, verify, etc.)
        +-- group.rs        Group operations (createGroup, groupSeal, groupOpen, etc.)
        +-- audit.rs        Audit log operations (createAuditEntry, verifyAuditLog, etc.)
        +-- identity.rs     Identity management (init, rotateKey, export/import)
        +-- stream.rs       Streaming operations (StreamSealer, StreamOpener wrappers)
        +-- http.rs         HTTP helpers (fetch_keys, put_keys, fetch_group, put_group)
    tests/
    +-- audit.rs            Integration tests: audit + envelope cross-module (4 tests)
    docs/
    +-- architecture.txt    Cryptographic design, PQ readiness, formats, security
    +-- api-reference.txt   Full method-by-method SDK documentation
    +-- integration-guide.txt   Step-by-step setup for consumers
    pkg/                    wasm-pack output (WASM + JS glue, ready to import)


BUILDING
--------

Prerequisites:

    - Rust toolchain (rustup.rs)
    - wasm-pack (cargo install wasm-pack)

Build the WASM package:

    wasm-pack build --target web

Run all tests:

    cargo test


LIVE DEMO
---------

A Docker Compose example is included in example/. It bundles a minimal
Express server (with SQLite storage) and a browser demo that exercises
every Veil feature -- all in one command:

    cd example
    docker compose up --build

    Open http://localhost:3000 and click "Run Demo".

What it demonstrates:

    1. Client initialization (key generation + upload)
    2. Direct seal / open (envelope encryption)
    3. Ed25519 signature verification
    4. Recipient management (add / remove)
    5. Reseal (hard revocation with fresh DEK)
    6. Group encryption (create group, seal, open)
    7. Streaming encryption (chunk-by-chunk)
    8. Audit log (create, anchor, verify)
    9. Identity export (PBKDF2 + AES-256-GCM backup)

The server stores everything in SQLite (example/data/veil.db). You can
inspect the database to verify the server never sees plaintext:

    sqlite3 example/data/veil.db "SELECT * FROM envelopes;"

The three tables (keys, groups, envelopes) are also rendered in the
browser UI below the demo log.

Architecture:

    example/
    +-- docker-compose.yml   docker compose up --build
    +-- Dockerfile           Multi-stage: Rust/wasm-pack -> Node.js
    +-- package.json         Express + better-sqlite3
    +-- server.js            4 Veil endpoints + envelope store + DB dump
    +-- public/
        +-- index.html       Interactive demo (loads WASM directly)

The server implements the four endpoints Veil expects:

    PUT /veil/keys/:userId        Store public keys
    GET /veil/keys/:userId        Fetch public keys
    PUT /veil/groups/:groupId     Store group bundle
    GET /veil/groups/:groupId     Fetch group bundle

Plus three demo-only endpoints:

    POST /veil/envelopes          Store an envelope (for the DB viewer)
    GET  /veil/db                 Dump all tables as JSON
    POST /veil/reset              Clear all data


DEPENDENCIES
------------

All cryptographic dependencies are from the RustCrypto and dalek-cryptography
projects, which are widely audited and used in production systems.

    x25519-dalek .......... X25519 Diffie-Hellman (key exchange, ECIES)
    ed25519-dalek ......... Ed25519 digital signatures (envelope signing)
    aes-gcm ............... AES-256-GCM authenticated encryption
    hkdf .................. HKDF-SHA256 (key derivation)
    sha2 .................. SHA-256 hash function
    pbkdf2 ................ PBKDF2-SHA256 (identity export key derivation)
    zeroize ............... Secure memory clearing for secret material
    base64ct .............. Constant-time base64 encoding/decoding
    getrandom ............. Cryptographic RNG (browser: crypto.getRandomValues)
    wasm-bindgen .......... Rust <-> JavaScript FFI bindings
    wasm-bindgen-futures .. Async/await support in WASM
    web-sys ............... Browser API bindings (fetch, localStorage, console)
    js-sys ................ JavaScript standard library bindings
    serde / serde_json .... JSON serialization

Browser APIs used (via inline JS shim, no extra web-sys features needed):
    crypto.subtle ......... WebCrypto (non-extractable AES-GCM key generation,
                            encrypt/decrypt for at-rest identity protection)
    indexedDB ............. IndexedDB (CryptoKey storage)

No runtime JavaScript dependencies. The entire SDK compiles to a single
WASM binary with auto-generated JS glue code.


LICENSE
-------

[Choose your license]


================================================================================
                              veil -- see nothing.
================================================================================
