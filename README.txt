
================================================================================

                        __      __  ______  __  __
                       /\ \    / / /\  ___\/\ \/\ \
                       \ \ \  / /  \ \  __\\ \ \ \ \
                        \ \_\/ /    \ \_____\ \_\ \_\
                         \/_/\/      \/_____/\/_/\/_/

                    End-to-end encryption for the web.
                    Post-quantum ready. Zero trust. Pure WASM.

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
        covers: "veil-sig-v1" || version || signer_id_len || signer_id ||
        ciphertext_len || ciphertext || metadata_len || metadata ||
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

   Opening does not verify the signature. Call verify() separately.

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
        SHA-256("veil-auto-group-v1:" || sorted_ids.join(":")) -> "auto:<base64>"

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


CRYPTOGRAPHIC DESIGN
--------------------

All primitives are from the RustCrypto ecosystem and the dalek-cryptography
project. No custom cryptography, no novel constructions.

    Identity Keys .......... X25519 (key exchange) + Ed25519 (signing)
    Key Wrapping ........... ECIES (ephemeral X25519 DH + HKDF + AES-GCM)
    Key Derivation ......... HKDF-SHA256 (context-bound: "veil-wrap" || keys)
    Symmetric Encryption ... AES-256-GCM (authenticated encryption)
    Streaming Encryption ... STREAM construction (AES-256-GCM per chunk)
    Envelope Signing ....... Ed25519 (deterministic signatures)
    Secret Zeroization ..... zeroize crate (Zeroizing<T> on all secrets)
    At-Rest Protection ..... WebCrypto non-extractable AES-256-GCM (IndexedDB)
    Identity Export ........ PBKDF2-SHA256 (600k iterations) + AES-256-GCM
    Key Distribution ....... Authenticated HTTP + TOFU key pinning (DH + signing)
    Random Number Gen ...... Browser crypto.getRandomValues (via getrandom)
    Key Directory .......... In-memory PublicKeyBundle cache + TOFU pinning
    GEK Caching ............ In-memory (group_id, epoch) -> GEK cache

POST-QUANTUM READINESS

The current primitives (X25519, Ed25519) are vulnerable to quantum computers
running Shor's algorithm. Veil's architecture is designed for a future migration
to post-quantum algorithms without breaking the API:

    Planned PQ migration:
        X25519 (DH)    -> ML-KEM-768  (Kyber, NIST FIPS 203)  ~1,184 byte pubkeys
        Ed25519 (sig)  -> ML-DSA-65   (Dilithium, NIST FIPS 204)  ~1,952 byte pubkeys

    Key size impact:
        Classical keys:  32 + 32 = 64 bytes per user
        PQ keys:         1,184 + 1,952 = 3,136 bytes per user

    Architectural mitigations (already implemented):
        - PublicKeyBundle: extensible struct ready for kem_public / pq_sign fields.
        - KeyCache: in-memory caching amortizes the cost of fetching large PQ keys.
        - Group envelopes: one KEM encapsulation per group (not per message).
        - GekCache: avoids redundant KEM decapsulation on cached groups.
        - Auto-group: transparent group management for recurring conversations.

    Migration path:
        1. Add PQ key fields to PublicKeyBundle (hybrid: classical + PQ).
        2. Update ECIES wrapping to use ML-KEM-768 encapsulation.
        3. Update envelope signing to use ML-DSA-65.
        4. Classical keys remain for backward compatibility during transition.
        5. No API changes needed — the TypeScript wrapper is unaffected.

Each wrap operation uses a fresh ephemeral key pair. Even wrapping the same
DEK for the same recipient twice produces different ciphertext.

The HKDF info string binds both the ephemeral and recipient public keys:
"veil-wrap" || ephemeral_public || recipient_public. The associated data
for key wrapping is the recipient's public key, binding the wrapped DEK to
its intended recipient and preventing key substitution.

DH outputs are validated via was_contributory() (RFC 7748 section 6) to
reject low-order points that would produce predictable shared secrets.

Envelope signatures use a deterministic payload format:
"veil-sig-v1" || version(1 byte) || signer_id_len(4 BE) || signer_id ||
ciphertext_len(4 BE) || ciphertext_base64 || has_metadata(1) ||
[metadata_len(4 BE) || metadata_json] || access_type(1) || access_data.
For direct envelopes, access_data is the sorted recipient list
(length-prefixed per-recipient fields). For group envelopes, it is the
group_id and wrapped_dek. All variable-length fields are length-prefixed
to prevent boundary ambiguity. The signature covers the full recipient
list, so adding or removing recipients requires re-signing.


ENVELOPE FORMAT
---------------

Envelopes are serialized as JSON:

    {
        "version": 1,
        "ciphertext": "<base64>",
        "recipients": [
            {
                "user_id": "alice",
                "ephemeral_public": "<base64>",
                "encrypted_dek": "<base64>"
            },
            {
                "user_id": "bob",
                "ephemeral_public": "<base64>",
                "encrypted_dek": "<base64>"
            }
        ],
        "metadata": { "type": "message", "timestamp": 1700000000 },
        "signer_id": "alice",
        "signature": "<base64>",
        "audit_hash": "<base64>"
    }

Optional fields:
  - metadata:    Unencrypted application data (omitted if not provided).
  - signer_id:   User ID of the sealer (present on all new envelopes).
  - signature:   Ed25519 signature over the envelope (present on all new
                 envelopes). Unsigned legacy envelopes can still be opened.
  - audit_hash:  SHA-256 hash of the latest audit log entry (chain head).
                 Links the envelope to its audit trail. Omitted if not set.

Group envelopes include two additional fields:
  - group_id:     Group identifier (present for group-encrypted envelopes).
                  Recipients list is empty; access is via the group key.
  - wrapped_dek:  DEK wrapped with the GEK (AES-256-GCM, base64).
                  AD = "veil-group-dek:" + group_id.

Group Key Bundle format:

    {
        "version": 1,
        "group_id": "team-engineering",
        "epoch": 1,
        "members": [
            {
                "user_id": "alice",
                "ephemeral_public": "<base64>",
                "encrypted_dek": "<base64>"
            }
        ],
        "signer_id": "alice",
        "signature": "<base64>"
    }

The `members` array wraps the 32-byte GEK per-member using ECIES (same
scheme as DEK wrapping). `epoch` starts at 1 and increments on GEK rotation
(member removal). The bundle is signed by the signer (creator or modifier).

Stream Header format:

    {
        "version": 1,
        "chunk_size": 65536,
        "nonce_prefix": "<base64, 8 bytes>",
        "recipients": [ ... ],
        "metadata": { "type": "file", "name": "report.pdf" },
        "signer_id": "alice",
        "signature": "<base64>",
        "group_id": "...",
        "wrapped_dek": "..."
    }

Per-recipient streams use `recipients` (same as envelope DEK wrapping).
Group streams use `group_id` + `wrapped_dek` (DEK wrapped with GEK).
Each encrypted chunk is binary: `is_final(1) || ciphertext || tag(16)`.

The envelope is opaque to the server and to the application. Pass it around
as a JSON string -- only Veil clients with the right private key can read it.


PROJECT STRUCTURE
-----------------

    src/
    +-- lib.rs              Module declarations and re-exports
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
every Veil feature — all in one command:

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
    ├── docker-compose.yml   # docker compose up --build
    ├── Dockerfile           # Multi-stage: Rust/wasm-pack → Node.js
    ├── package.json         # Express + better-sqlite3
    ├── server.js            # 4 Veil endpoints + envelope store + DB dump
    └── public/
        └── index.html       # Interactive demo (loads WASM directly)

The server implements the four endpoints Veil expects:

    PUT /veil/keys/:userId        Store public keys
    GET /veil/keys/:userId        Fetch public keys
    PUT /veil/groups/:groupId     Store group bundle
    GET /veil/groups/:groupId     Fetch group bundle

Plus three demo-only endpoints:

    POST /veil/envelopes          Store an envelope (for the DB viewer)
    GET  /veil/db                 Dump all tables as JSON
    POST /veil/reset              Clear all data


INTEGRATION GUIDE
-----------------

STEP 1: ADD THE WASM MODULE TO YOUR WEB APPLICATION

Copy the contents of pkg/ into your static assets, or publish it to npm
and install it as a dependency.

    your-app/
    +-- static/
    |   +-- veil_bg.wasm
    |   +-- veil.js
    +-- index.html


STEP 2: IMPLEMENT THE SERVER ENDPOINTS

Veil requires your server to implement two REST endpoints for public key
distribution. When an auth_token is provided to VeilClient.init(), all
requests include an Authorization: Bearer <token> header.

    PUT /veil/keys/:userId

        Stores a user's public keys. Called once during initialization.
        The server MUST validate that only the key owner can update their keys
        (check the Bearer token against the userId).

        Request body:
        {
            "publicKey": "<base64>",
            "signingKey": "<base64>"
        }
        Headers:  Authorization: Bearer <token>  (if auth_token provided)
        Response: 200 OK

    GET /veil/keys/:userId

        Fetches a user's public keys.

        Response body:
        {
            "publicKey": "<base64>",
            "signingKey": "<base64>"
        }
        Headers:  Authorization: Bearer <token>  (if auth_token provided)
        Error: 404 if user not found

Example server implementation (pseudocode):

    keys = {}

    on PUT /veil/keys/:userId:
        assert request.user == userId    // auth check
        keys[userId] = {
            publicKey: request.body.publicKey,
            signingKey: request.body.signingKey,
        }
        respond 200

    on GET /veil/keys/:userId:
        entry = keys[userId]
        if not entry: respond 404
        respond { "publicKey": entry.publicKey, "signingKey": entry.signingKey }

In production, store keys in your database alongside user accounts.
Both keys are uploaded once and change only if the user reinitializes.

    PUT /veil/groups/:groupId

        Stores a group key bundle. Called when creating/updating a group.
        The server MUST validate that only authorized group members can
        update the bundle (check the Bearer token).

        Request body: GroupKeyBundle JSON (see ENVELOPE FORMAT below)
        Headers:  Authorization: Bearer <token>  (if auth_token provided)
        Response: 200 OK

    GET /veil/groups/:groupId

        Fetches a group key bundle.

        Response body: GroupKeyBundle JSON
        Headers:  Authorization: Bearer <token>  (if auth_token provided)
        Error: 404 if group not found


STEP 3: USE THE SDK IN YOUR FRONTEND

    import init, { VeilClient } from "./static/veil.js";

    // Initialize the WASM module (must be called once)
    await init();

    // Initialize the Veil client. Generates (or loads) identity keys
    // (X25519 for encryption + Ed25519 for signing) and uploads public
    // keys to the server.
    const alice = await VeilClient.init("alice", "https://yourserver.com", authToken);

    // On first initialization, prompt the user to back up their key.
    if (alice.isNewIdentity()) {
        const blob = alice.exportIdentity(userPassword);
        // Store blob securely (e.g., let user download it)
    }

    // Check if the identity key is protected by at-rest encryption.
    // Returns false if IndexedDB was unavailable (fallback to plaintext).
    console.log("Key protected:", alice.isKeyProtected());

    // Seal data for one or more recipients.
    // Alice is always included as a recipient automatically.
    // Optional metadata (3rd argument) is stored unencrypted.
    const envelope = await alice.seal(
        "alice@mail.com",
        ["bob"],
        JSON.stringify({ type: "email", timestamp: Date.now() })
    );

    // Store the envelope wherever you like (database, API, etc.)
    // It is just an opaque JSON string.
    await fetch("/api/user/alice/email", {
        method: "PUT",
        body: envelope,
    });


STEP 4: ANOTHER USER OPENS THE ENVELOPE

    const bob = await VeilClient.init("bob", "https://yourserver.com", bobAuthToken);

    // Fetch the envelope from your API
    const envelope = await fetch("/api/user/alice/email").then(r => r.text());

    // Verify the signature (optional but recommended)
    await bob.verify(envelope);

    // Open it -- Veil finds Bob's wrapped key, unwraps the DEK, decrypts.
    const email = bob.open(envelope);
    // email === "alice@mail.com"


STEP 5: GRANT OR REVOKE ACCESS

    // Alice wants to grant access to Charlie
    const updated = await alice.addRecipient(envelope, "charlie");
    // Store the updated envelope (it now has 3 recipients)
    // The envelope is re-signed by Alice.

    // Alice wants to revoke Bob's access (soft)
    const revoked = alice.removeRecipient(updated, "bob");
    // Bob can no longer unwrap the DEK from this envelope

    // For hard revocation -- re-encrypt with a new DEK
    const resealed = await alice.reseal(revoked, ["charlie"]);
    // Even if Bob cached the old DEK, it no longer decrypts the data.
    // The resealed envelope is signed by Alice.


PRACTICAL EXAMPLE: ENCRYPTED USER PROFILE
------------------------------------------

Suppose you have a Python REST API with a /user/:id endpoint. You want to
encrypt the user's email so the server never sees it.

    // On signup -- Alice seals her email for herself
    const alice = await VeilClient.init("alice", "/veil", aliceToken);
    const sealed = await alice.seal("alice@mail.com", []);
    await fetch("/api/user/alice", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: sealed }),
    });

    // Later -- Bob needs Alice's email
    // Step 1: Bob requests access (your app logic)
    // Step 2: Alice's client grants access
    const envelope = await fetch("/api/user/alice")
        .then(r => r.json())
        .then(j => j.email);
    const updated = await alice.addRecipient(envelope, "bob");
    await fetch("/api/user/alice", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: updated }),
    });

    // Step 3: Bob can now decrypt
    const bob = await VeilClient.init("bob", "/veil", bobToken);
    const envelope2 = await fetch("/api/user/alice")
        .then(r => r.json())
        .then(j => j.email);

    // Verify the envelope was sealed by Alice
    await bob.verify(envelope2);

    const email = bob.open(envelope2);
    // email === "alice@mail.com"

The server stores the envelope as an opaque JSON blob. It never sees the
email address. Only authorized recipients can decrypt it.


API REFERENCE
-------------

VeilClient.init(userId, serverUrl, authToken?)

    Static async constructor. Creates a new VeilClient instance.

    Parameters:
        userId      string    A unique identifier for this user.
        serverUrl   string    Base URL for the server.
                              Example: "/veil" or "https://api.example.com"
        authToken   string?   Optional Bearer token included in all HTTP
                              requests. The server should validate that only
                              the key owner can update their keys.

    Returns:        Promise<VeilClient>

    Behavior:
        - Loads or generates an X25519 + Ed25519 key pair.
        - Encrypts the secret keys with a non-extractable WebCrypto key
          (stored in IndexedDB) before persisting to localStorage.
          Falls back to plaintext if IndexedDB is unavailable.
        - Uploads both public keys to the server via PUT /veil/keys/:userId.
        - Legacy keys (DH-only, plaintext) are automatically migrated to
          the encrypted dual-key format on load.

    Errors:
        - localStorage is not available or access is denied.
        - The PUT request to the server fails.
        - A previously encrypted key cannot be decrypted (IndexedDB cleared
          but localStorage was not). Use importIdentity() to recover.

--------

client.publicKey()

    Returns the user's X25519 public key as a base64 string.

    Parameters:     (none)
    Returns:        string (44 characters, base64)

--------

client.signingKey()

    Returns the user's Ed25519 signing public key as a base64 string.

    Parameters:     (none)
    Returns:        string (44 characters, base64)

--------

client.userId()

    Returns the user ID this client was initialized with.

    Parameters:     (none)
    Returns:        string

--------

client.isNewIdentity()

    Whether this client has a freshly generated identity key. If true, the
    app should prompt the user to call exportIdentity() to create a backup.

    Parameters:     (none)
    Returns:        boolean

--------

client.isKeyProtected()

    Whether the identity key is protected by at-rest encryption (non-
    extractable WebCrypto key in IndexedDB). Returns false if IndexedDB
    was unavailable and the key is stored as plaintext in localStorage.

    Parameters:     (none)
    Returns:        boolean

--------

client.wasRotated()

    Whether this client was created via key rotation (rotateKey()).
    Returns false for clients created via init() or importIdentity().

    Parameters:     (none)
    Returns:        boolean

--------

VeilClient.rotateKey(userId, serverUrl, authToken?)

    Static async constructor. Generates a fresh X25519 + Ed25519 key pair,
    overwrites local storage, and uploads the new public keys to the server.
    Returns a new VeilClient; the old instance is stale.

    Recipients must call trustKey(userId) to accept the new keys (TOFU pins
    will reject the old keys). Use reseal() on existing envelopes to re-wrap
    with the new identity.

    Parameters:
        userId      string    The user whose keys to rotate.
        serverUrl   string    Base URL for the server.
        authToken   string?   Optional Bearer token.

    Returns:        Promise<VeilClient>

    Behavior:
        - Generates fresh X25519 + Ed25519 key pairs.
        - Encrypts and stores the new secret keys (same at-rest protection
          as init()).
        - Uploads both new public keys to the server via PUT /veil/keys/:userId.
        - client.wasRotated() returns true.
        - client.isNewIdentity() returns false.

    Errors:
        - localStorage / IndexedDB access fails.
        - The PUT request to the server fails.

--------

client.exportIdentity(password)

    Exports the identity keys (DH + signing) encrypted with a user-provided
    password. Returns a base64-encoded blob that can be imported on another
    device using VeilClient.importIdentity().

    Uses PBKDF2-SHA256 (600,000 iterations) + AES-256-GCM.
    Blob format (v2): version(2) || salt(16) || nonce(12) ||
    ciphertext(dh_secret[32] || sign_secret[32]) + tag.

    Parameters:
        password    string    Password to encrypt the export blob.
                              Must be at least 16 characters.

    Returns:        string    Base64-encoded encrypted blob.

    Errors:
        - Password is shorter than 16 characters.
        - Encryption fails (should not happen in practice).

--------

VeilClient.importIdentity(userId, serverUrl, blobB64, password, authToken?)

    Static async constructor. Imports identity keys from an encrypted blob
    (created by exportIdentity()) and initializes a client.

    Handles both v1 (DH-only, generates a new signing key) and v2
    (DH + signing) export formats.

    Parameters:
        userId      string    User ID for this identity.
        serverUrl   string    Base URL for the server.
        blobB64     string    Base64-encoded export blob.
        password    string    Password used when exporting.
        authToken   string?   Optional Bearer token.

    Returns:        Promise<VeilClient>

    Errors:
        - Wrong password or corrupted blob.
        - Server communication fails.

--------

client.trustKey(userId)

    Clears the TOFU (Trust-On-First-Use) key pins (both DH and signing)
    for a user. Call this when a legitimate key rotation has occurred and
    you want to accept the user's new public keys.

    Parameters:
        userId      string    The user whose pins should be cleared.

    Returns:        void

    Errors:
        - localStorage access fails.

--------

client.seal(plaintext, recipientIds, metadataJson?)

    Encrypts data and wraps the DEK for each recipient. The envelope is
    signed with the caller's Ed25519 key.

    Parameters:
        plaintext       string      The data to encrypt (UTF-8).
        recipientIds    string[]    User IDs of additional recipients.
        metadataJson    string?     Optional JSON string of unencrypted
                                    metadata (e.g. sender, type, timestamp).

    Returns:            Promise<string>    Envelope as a JSON string.

    Behavior:
        - Generates a random DEK.
        - Encrypts the plaintext with AES-256-GCM.
        - Fetches each recipient's public keys from the server.
        - Wraps the DEK for each recipient and for the caller.
        - Signs the envelope with the caller's Ed25519 key.
        - Returns the serialized Envelope.

    Errors:
        - A recipient's public keys cannot be fetched (404).

--------

client.open(envelopeJson)

    Decrypts an envelope.

    Parameters:
        envelopeJson    string    The Envelope JSON string.

    Returns:            string    The decrypted plaintext.

    Behavior:
        - Finds the WrappedKey matching our user ID.
        - Unwraps the DEK using our secret key.
        - Decrypts the ciphertext.

    Errors:
        - We are not a recipient of this envelope.
        - The envelope is corrupted or tampered with.

    Note: This is a synchronous operation (no server call needed).
    Does not verify the signature -- call verify() or verifyAndOpen()
    separately.

--------

client.verifyAndOpen(envelopeJson)

    Verifies the Ed25519 signature and decrypts a direct envelope in one
    async call. Fetches the signer's key, verifies the signature, then
    opens the envelope.

    Parameters:
        envelopeJson    string    The Envelope JSON string.

    Returns:            Promise<string>    The decrypted plaintext.

    Behavior:
        - Parses the envelope and extracts the signer_id.
        - Fetches the signer's signing public key from the server.
        - TOFU-verifies the signing key against the local pin.
        - Verifies the Ed25519 signature.
        - Unwraps the DEK and decrypts the ciphertext.

    Errors:
        - The envelope is unsigned (no signer_id or signature).
        - The envelope is a group envelope (use groupOpen() instead).
        - The signer's public key cannot be fetched.
        - The signing key has changed (TOFU mismatch).
        - Signature verification fails.
        - Caller is not a recipient or decryption fails.

--------

client.verify(envelopeJson)

    Verifies the Ed25519 signature on an envelope. Fetches the signer's
    public signing key from the server and TOFU-verifies it.

    Parameters:
        envelopeJson    string    The Envelope JSON string.

    Returns:            Promise<void>    Resolves if valid.

    Behavior:
        - Parses the envelope and extracts the signer_id.
        - Fetches the signer's signing public key from the server.
        - TOFU-verifies the signing key against the local pin.
        - Verifies the Ed25519 signature over the signed payload.

    Errors:
        - The envelope is unsigned (no signer_id or signature).
        - The signer's public key cannot be fetched.
        - The signing key has changed (TOFU mismatch).
        - Signature verification fails (tampered envelope).

--------

client.addRecipient(envelopeJson, recipientId)

    Adds a new recipient to an existing envelope.

    Parameters:
        envelopeJson    string    The Envelope JSON string.
        recipientId     string    User ID of the new recipient.

    Returns:            Promise<string>    Updated Envelope as JSON.

    Behavior:
        - Unwraps the DEK (caller must be an existing recipient).
        - Fetches the new recipient's public keys from the server.
        - Wraps the DEK for the new recipient.
        - Returns the envelope with the new recipient appended.
        - The envelope is re-signed by the caller.

    Errors:
        - Caller is not a recipient (cannot unwrap DEK).
        - Recipient already exists in the envelope.
        - New recipient's public keys cannot be fetched.

--------

client.removeRecipient(envelopeJson, recipientId)

    Removes a recipient from an envelope (soft revocation).

    Parameters:
        envelopeJson    string    The Envelope JSON string.
        recipientId     string    User ID to remove.

    Returns:            string    Updated Envelope as JSON.

    Behavior:
        - Removes the WrappedKey for the specified recipient.
        - Does NOT re-encrypt the data (soft revocation).
        - The envelope is re-signed by the caller.

    Errors:
        - Recipient not found in the envelope.
        - Removing would leave the envelope with no recipients.

    Note: This is a synchronous, local operation. For hard revocation
    (ensuring the removed user can never decrypt), call reseal().

--------

client.reseal(envelopeJson, recipientIds, metadataJson?)

    Re-seals an envelope with a fresh DEK (hard revocation).

    Parameters:
        envelopeJson    string      The Envelope JSON string.
        recipientIds    string[]    User IDs of recipients (excluding self).
        metadataJson    string?     Optional new metadata JSON. If omitted,
                                    the original metadata is preserved.

    Returns:            Promise<string>    New Envelope as JSON.

    Behavior:
        - Decrypts the data (caller must be a recipient).
        - Generates a new DEK and re-encrypts.
        - Wraps the new DEK for the caller and each recipient.
        - Signs the new envelope with the caller's Ed25519 key.
        - Returns a fresh envelope. Old DEKs are useless.

    Errors:
        - Caller is not a recipient of the original envelope.
        - A recipient's public keys cannot be fetched.

--------

client.createAuditEntry(action, targetId?, timestamp, prevHash?)

    Creates a signed audit log entry. Entries form a hash chain: each
    entry includes the SHA-256 of the previous entry, making the log
    append-only and tamper-evident.

    Parameters:
        action      string    The action performed: "seal", "grant",
                              "revoke", or "reseal".
        targetId    string?   The affected user (for grant/revoke).
                              Pass null for seal/reseal.
        timestamp   number    Caller-provided Unix milliseconds
                              (e.g. Date.now()).
        prevHash    string?   The entry_hash of the previous entry,
                              or null for the genesis entry.

    Returns:        string    AuditEntry as a JSON string.

    Behavior:
        - Computes a canonical payload: "veil-audit-v1" || action ||
          actor_id || target_id || timestamp || prev_hash.
        - Hashes the payload (SHA-256) to produce entry_hash.
        - Signs the payload with the caller's Ed25519 key.
        - The genesis entry uses SHA-256("") as its prev_hash.

    Errors:
        - prev_hash is not valid base64.

--------

client.anchorAudit(envelopeJson, auditEntryJson)

    Sets the audit_hash field on an envelope to the given entry's
    entry_hash. This links the envelope to its audit trail.

    Parameters:
        envelopeJson      string    The Envelope JSON string.
        auditEntryJson    string    The AuditEntry JSON string.

    Returns:              string    Updated Envelope as JSON.

    Note: This is a local operation. The audit_hash is not covered by
    the envelope signature, so anchoring does not invalidate it.

    Errors:
        - Either JSON argument is malformed.

--------

client.verifyAuditLog(envelopeJson, auditEntriesJson)

    Verifies an audit log against an envelope.

    Parameters:
        envelopeJson        string    The Envelope JSON string.
        auditEntriesJson    string    JSON array of AuditEntry objects.

    Returns:                Promise<void>    Resolves if valid.

    Behavior:
        - Fetches each actor's signing key from the server.
        - Verifies each entry's hash and Ed25519 signature.
        - Verifies hash-chain linkage (each prev_hash matches the
          previous entry_hash, genesis uses SHA-256("")).
        - Verifies that the envelope's audit_hash matches the chain
          head (the last entry's entry_hash).

    Errors:
        - An actor's signing key cannot be fetched.
        - An entry's hash or signature is invalid.
        - The hash chain is broken.
        - The envelope's audit_hash does not match the chain head.
        - The envelope has no audit_hash.

--------

client.createGroup(groupId, memberIds)

    Creates a new group. Generates a Group Encryption Key (GEK), wraps it
    for each member (including the caller) using ECIES, signs the bundle,
    and uploads it to the server.

    Parameters:
        groupId     string      Unique identifier for the group.
        memberIds   string[]    User IDs of other members (caller is
                                included automatically).

    Returns:        Promise<string>    GroupKeyBundle as JSON.

    Errors:
        - A member's public keys cannot be fetched.
        - The PUT request to the server fails.

--------

client.addGroupMember(groupId, memberId)

    Adds a member to an existing group. Fetches the bundle, unwraps the
    GEK, wraps for the new member, re-signs, and uploads.

    Parameters:
        groupId     string    The group to modify.
        memberId    string    User ID of the new member.

    Returns:        Promise<string>    Updated GroupKeyBundle as JSON.

    Behavior:
        - Same epoch (no GEK rotation). New member gets the existing GEK.
        - Bundle is re-signed by the caller.

    Errors:
        - Caller is not a group member.
        - Member already exists.
        - New member's public keys cannot be fetched.

--------

client.removeGroupMember(groupId, memberId)

    Removes a member from a group (rotates the GEK).

    Parameters:
        groupId     string    The group to modify.
        memberId    string    User ID of the member to remove.

    Returns:        Promise<string>    Updated GroupKeyBundle as JSON.

    Behavior:
        - Generates a NEW GEK (epoch incremented by 1).
        - Wraps the new GEK for remaining members.
        - The removed member's old GEK cannot decrypt new envelopes.
        - Fetches public keys for all remaining members.
        - Bundle is re-signed by the caller.

    Errors:
        - Member not found in the group.
        - Removing would leave the group empty.
        - A remaining member's public keys cannot be fetched.

--------

client.groupSeal(plaintext, groupId, metadataJson?)

    Seals data for a group. Fetches the group bundle, unwraps the GEK,
    encrypts data with a fresh DEK, wraps the DEK with the GEK.

    Parameters:
        plaintext       string    The data to encrypt (UTF-8).
        groupId         string    The group to seal for.
        metadataJson    string?   Optional JSON metadata.

    Returns:            Promise<string>    Envelope as JSON.

    Behavior:
        - Generates a random DEK, encrypts plaintext (AES-256-GCM).
        - Wraps DEK with GEK (AES-256-GCM, AD = "veil-group-dek:" + groupId).
        - Signs the envelope (group_id included in the signed payload).
        - Envelope has empty recipients list and group_id/wrapped_dek set.

    Errors:
        - Caller is not a group member.
        - Group bundle cannot be fetched.

--------

client.groupOpen(envelopeJson)

    Opens a group-encrypted envelope. Fetches the group bundle, unwraps
    the GEK, unwraps the DEK, and decrypts.

    Parameters:
        envelopeJson    string    The Envelope JSON string.

    Returns:            Promise<string>    The decrypted plaintext.

    Behavior:
        - Reads group_id from the envelope.
        - If the envelope is signed: fetches the signer's key, verifies
          the signature. Unsigned envelopes still work (backward compat).
        - Fetches the group's bundle from the server.
        - Unwraps the GEK using the caller's identity key.
        - Unwraps the DEK using the GEK.
        - Decrypts the ciphertext.

    Errors:
        - Envelope is not a group envelope (no group_id).
        - Signed envelope missing signer_id.
        - Signature verification fails.
        - Caller is not a group member.
        - Decryption fails.

--------

client.sealStreamInit(recipientIds, metadataJson?, chunkSize?)

    Initializes a streaming sealer for per-recipient encryption.

    Parameters:
        recipientIds    string[]    User IDs of recipients.
        metadataJson    string?     Optional JSON metadata.
        chunkSize       number?     Chunk size in bytes (default 65536).

    Returns:            Promise<StreamSealer>

    Behavior:
        - Generates a random DEK and 8-byte nonce prefix.
        - Fetches each recipient's public keys from the server.
        - Wraps the DEK for each recipient and for the caller.
        - Signs the StreamHeader with the caller's Ed25519 key.
        - Returns a StreamSealer ready to encrypt chunks.

    Errors:
        - A recipient's public keys cannot be fetched.
        - Duplicate recipient ID in the list.
        - Caller (sealer) is also in the recipient list.
        - chunk_size is zero.

--------

StreamSealer.header()

    Returns the StreamHeader as a JSON string. Send/store this before
    the encrypted chunks.

    Parameters:     (none)
    Returns:        string (JSON)

--------

StreamSealer.sealChunk(chunk, isLast)

    Encrypts a chunk of plaintext.

    Parameters:
        chunk       Uint8Array    The plaintext bytes.
        isLast      boolean       True for the final chunk.

    Returns:        Uint8Array    Encrypted chunk bytes.

    Errors:
        - Stream is already finalized.
        - Chunk index overflow (> 4 billion chunks).

    Note: After calling with isLast=true, the sealer is finalized and
    no more chunks can be sealed. Call free() to release WASM memory.

--------

client.openStreamInit(headerJson)

    Initializes a streaming opener for per-recipient decryption.

    Parameters:
        headerJson    string    StreamHeader as JSON.

    Returns:          StreamOpener

    Behavior:
        - Finds the caller's wrapped DEK in the header.
        - Unwraps the DEK using the caller's secret key.
        - Returns a StreamOpener ready to decrypt chunks.

    Errors:
        - Caller is not a recipient.
        - Invalid header format.

    Note: This is a synchronous operation (no server call needed).
    Does not verify the header signature -- call verifyStreamHeader()
    separately.

--------

client.verifyStreamHeader(headerJson)

    Verifies the Ed25519 signature on a stream header. Fetches the
    signer's public signing key from the server and TOFU-verifies it.

    Use this after openStreamInit() for direct streams that need
    signature verification.

    Parameters:
        headerJson    string    StreamHeader as JSON.

    Returns:          Promise<void>    Resolves if valid.

    Behavior:
        - Parses the header and extracts the signer_id.
        - Fetches the signer's signing public key from the server.
        - TOFU-verifies the signing key against the local pin.
        - Verifies the Ed25519 signature over the header payload.

    Errors:
        - Header is unsigned (no signer_id or signature).
        - The signer's public key cannot be fetched.
        - The signing key has changed (TOFU mismatch).
        - Signature verification fails.

--------

StreamOpener.openChunk(encryptedChunk)

    Decrypts a chunk.

    Parameters:
        encryptedChunk    Uint8Array    Encrypted chunk bytes.

    Returns:              Uint8Array    Decrypted plaintext bytes.

    Errors:
        - Stream is already finished.
        - Chunk too short (< 17 bytes).
        - Decryption fails (tampered, wrong order, wrong DEK).

--------

StreamOpener.isDone()

    Whether the final chunk has been processed.

    Parameters:     (none)
    Returns:        boolean

--------

client.groupSealStreamInit(groupId, metadataJson?, chunkSize?)

    Initializes a streaming sealer for group encryption.

    Parameters:
        groupId         string      The group to seal for.
        metadataJson    string?     Optional JSON metadata.
        chunkSize       number?     Chunk size in bytes (default 65536).

    Returns:            Promise<StreamSealer>

    Behavior:
        - Fetches the group's bundle and unwraps the GEK.
        - Generates a random DEK and wraps it with the GEK.
        - Signs the StreamHeader (includes group_id).
        - Returns a StreamSealer ready to encrypt chunks.

    Errors:
        - Caller is not a group member.
        - Group bundle cannot be fetched.

--------

client.groupOpenStreamInit(headerJson)

    Initializes a streaming opener for group decryption.

    Parameters:
        headerJson    string    StreamHeader as JSON.

    Returns:          Promise<StreamOpener>

    Behavior:
        - If the header is signed: fetches the signer's key, verifies
          the signature. Unsigned headers still work (backward compat).
        - Reads group_id from the header.
        - Fetches the group's bundle and unwraps the GEK.
        - Unwraps the DEK using the GEK.
        - Returns a StreamOpener ready to decrypt chunks.

    Errors:
        - Signed header missing signer_id.
        - Signature verification fails.
        - Header is not a group stream.
        - Caller is not a group member.

--------

client.autoSeal(plaintext, recipientIds, metadataJson?)

    Seals data using a transparent auto-group. Computes a deterministic
    group ID from the sorted participant list, creates the group if it
    doesn't exist, and seals via groupSeal.

    Parameters:
        plaintext       string      The data to encrypt (UTF-8).
        recipientIds    string[]    User IDs of recipients.
        metadataJson    string?     Optional JSON metadata.

    Returns:            Promise<string>    Envelope as JSON.

    Behavior:
        - Computes auto-group ID: SHA-256("veil-auto-group-v1:" +
          sorted unique participant IDs joined by ":") -> "auto:<base64>".
        - Checks if the group exists (GET /veil/groups/:groupId).
        - If not found, creates it (createGroup with all participants).
        - Seals via groupSeal with the auto-group ID.

    Errors:
        - A participant's public keys cannot be fetched.
        - Group creation or sealing fails.

--------

client.autoOpen(envelopeJson)

    Opens an envelope, transparently dispatching between direct and group
    decryption based on the envelope contents.

    Parameters:
        envelopeJson    string    The Envelope JSON string.

    Returns:            Promise<string>    The decrypted plaintext.

    Behavior:
        - Parses the envelope and checks for group_id.
        - If group_id is present: opens via groupOpen.
        - If no group_id: opens via direct open.

    Errors:
        - Caller is not a recipient or group member.
        - Decryption fails.

--------

client.invalidateGroupCache(groupId)

    Invalidates the cached GEK for a group. Call this after external
    group modifications (e.g. member removal by another user).

    Parameters:
        groupId     string    The group whose cache entry to clear.

    Returns:        void

--------

client.clearCaches()

    Clears all in-memory caches (key cache and GEK cache). Call this
    when the client should re-fetch everything from the server.

    Parameters:     (none)
    Returns:        void


SECURITY PROPERTIES
-------------------

WHAT VEIL PROVIDES

    Authenticated encryption
        AES-256-GCM provides both confidentiality and integrity.
        Any tampering with ciphertext, nonce, or associated data is
        detected and causes decryption to fail.

    Sender authentication (Ed25519 signatures)
        Every sealed envelope is signed with the sealer's Ed25519 key.
        Recipients can verify who created the envelope by calling
        verify(). The signature covers the version, signer ID,
        ciphertext, metadata, and the full access data (recipient list
        for direct envelopes, group info for group envelopes). Adding
        or removing recipients requires re-signing the envelope.

    Per-recipient key isolation
        Each recipient's wrapped DEK is bound to their public key via
        the AEAD associated data. A wrapped key cannot be moved to a
        different recipient.

    Ephemeral key wrapping
        Each wrap operation uses a fresh X25519 key pair. Compromise of
        one ephemeral key does not affect other wraps.

    Context-bound key derivation
        HKDF info binds both the ephemeral and recipient public keys,
        preventing cross-context key confusion.

    Low-order point rejection
        DH outputs are validated via was_contributory() to reject
        degenerate public keys (all-zeros, small-subgroup).

    Secret memory zeroization
        All secret material (DH secrets, signing secrets, DEKs, wrapping
        keys) is wrapped in Zeroizing<T> and automatically cleared when
        dropped.

    At-rest key protection
        The identity secret keys (DH + signing) are encrypted with a
        non-extractable WebCrypto AES-256-GCM CryptoKey stored in
        IndexedDB. This protects against localStorage-only theft
        (browser backups, sync, extensions reading storage without code
        execution).

    TOFU key pinning
        On first contact with a user, both their DH and signing public
        keys are pinned in localStorage. Subsequent fetches verify
        against the pins. If either key has changed, the operation fails
        with a clear warning. trustKey() allows accepting legitimate key
        rotations.

    Authenticated key distribution
        An optional Bearer auth token is included in all HTTP requests,
        enabling the server to enforce that only the key owner can
        update their public keys.

    Password-based identity export
        PBKDF2-SHA256 (600,000 iterations) + AES-256-GCM protects
        exported identity keys for cross-device recovery. The export
        blob includes both DH and signing secrets. A minimum password
        length of 16 characters is enforced.

    Server zero-knowledge
        The server never sees plaintext, DEKs, or private keys.
        It stores and serves public keys and opaque envelopes.

    Group key rotation on member removal
        removeGroupMember() generates a new GEK (incrementing the
        epoch) and re-wraps for remaining members. The removed
        member's old GEK cannot decrypt envelopes sealed after
        the rotation.

    Hard revocation
        reseal() generates a new DEK and re-encrypts the data. Even
        if a removed user cached the old DEK, it no longer works.

    Streaming chunk authentication
        Each chunk is encrypted with a unique nonce (random prefix +
        counter) and authenticated with associated data that binds the
        chunk index and finality flag. Reordering, duplication, or
        truncation of chunks causes decryption to fail.

    Tamper-evident audit trail
        Audit log entries form a SHA-256 hash chain with Ed25519
        signatures. Each entry records who performed what action and
        when. Chain linkage makes the log append-only: inserting,
        deleting, or reordering entries is detectable. The envelope's
        audit_hash field anchors the log to the envelope, ensuring
        the audit trail matches the current state.

    Key caching with epoch-bound staleness detection
        The KeyCache stores public key bundles in memory, reducing
        server round-trips. The GekCache stores unwrapped GEKs keyed
        by (group_id, epoch), so stale entries from before a key
        rotation are automatically rejected. Both caches are invalidated
        by trustKey() and clearCaches().

    Deterministic auto-group IDs
        Auto-group IDs are computed from a sorted, deduplicated list of
        participant IDs via SHA-256. The same set of participants always
        produces the same group ID, regardless of order or duplicates.
        The "veil-auto-group-v1:" domain separator prevents collisions
        with manually created group IDs.

    Post-quantum readiness
        The architecture (group envelopes, key caching, extensible key
        bundles) is designed to absorb the cost of PQ key sizes (3+ KB
        per user) without per-message overhead explosion. A future
        migration to ML-KEM-768 + ML-DSA-65 requires only internal
        changes — the API surface remains unchanged.

REMAINING RISKS

    Full XSS with code execution
        An attacker who can run arbitrary JavaScript can call
        crypto.subtle.decrypt() with the CryptoKey from IndexedDB.
        The non-extractable flag prevents exporting the key but not
        using it. This is a fundamental browser limitation.

    Active MITM before first contact
        TOFU key pinning protects against key substitution after the
        first contact, but not during it. Mitigations:
          * Always use HTTPS.
          * Provide the auth_token to authenticate key operations.
          * Allow users to verify public keys out-of-band.

    Soft revocation is not true revocation
        Removing a recipient's wrapped key prevents future unwrapping,
        but a user who previously decrypted the envelope may have cached
        the DEK. Use reseal() for true revocation.

    IndexedDB cleared without localStorage
        If a user clears IndexedDB but not localStorage, the encrypted
        identity keys become undecryptable. The user must recover via
        importIdentity() with their password-encrypted backup blob.

    Metadata
        Veil encrypts data content, not metadata. The server knows which
        users have public keys, can observe envelope sizes, and can read
        any unencrypted metadata attached to envelopes.

RECOMMENDATIONS FOR PRODUCTION USE

    1. Always serve your application over HTTPS.

       Veil encrypts data end-to-end, but TOFU key pinning relies on the
       first key fetch being legitimate. Without HTTPS, an active network
       attacker can substitute public keys during the initial exchange.
       HTTPS ensures the transport layer is authenticated before TOFU pins
       are established.

    2. Pass an auth_token to VeilClient.init() to authenticate key ops.

       Without an auth token, anyone can overwrite a user's public keys on
       the server. The token lets your server enforce that only the key owner
       can PUT to /veil/keys/:userId. Use your existing session or JWT tokens.

    3. Rate-limit the key endpoints to prevent abuse.

       The GET /veil/keys/:userId endpoint is called whenever a user seals
       data for a recipient (unless cached). Without rate limiting, a
       malicious client could enumerate all user IDs or flood the endpoint.
       Apply standard rate limiting per-IP and per-authenticated-user.

    4. Prompt users to exportIdentity() on first init (isNewIdentity()).

       Identity keys are stored locally (localStorage + IndexedDB). If
       the user clears browser data, switches devices, or IndexedDB is
       wiped, the keys are lost. exportIdentity() creates a password-
       encrypted backup blob that can be imported elsewhere. Show a
       one-time prompt when isNewIdentity() returns true, and let the
       user download or copy the blob.

    5. Use reseal() for hard revocation rather than just removing recipients.

       removeRecipient() is a soft revocation: it removes the wrapped DEK
       from the envelope, but if the removed user previously decrypted the
       data and cached the DEK, they can still decrypt. reseal() generates
       a new DEK, re-encrypts the data, and re-wraps for remaining
       recipients -- making previously cached DEKs useless. Always reseal
       when revoking access to sensitive data.

    6. Call verify() after opening envelopes to authenticate the sender.

       open() decrypts without verifying the signature. This is by design
       (verification requires a server call to fetch the signer's key).
       For sensitive workflows, always call verify() or use verifyAndOpen()
       to confirm the envelope was created by the claimed sender. This
       prevents a recipient from forging envelopes that appear to come
       from someone else.

    7. Only include non-sensitive data in envelope metadata (it is not encrypted).

       The metadata field is stored in plaintext alongside the encrypted
       ciphertext. It is visible to the server and anyone with access to
       the stored envelope. Use it for routing, indexing, or display
       purposes (e.g. message type, timestamp, sender name) -- never for
       data that should be confidential.

    8. Consider adding envelope expiry or versioning at the application level.

       Veil envelopes do not expire -- they are decryptable as long as the
       recipient holds the correct private key. If your application needs
       time-limited access, implement expiry at the application layer
       (e.g. a "valid_until" field in metadata, enforced by your backend
       before serving the envelope). Similarly, if you need to track
       envelope versions (e.g. after reseal), use metadata or your own
       database fields.

    9. Use autoSeal/autoOpen for recurring conversations (DMs, threads).

       For conversations between the same set of participants, autoSeal
       creates a deterministic group key on first use and reuses it for
       subsequent messages. This amortizes the per-recipient ECIES wrapping
       cost: one KEM operation per group creation instead of one per message
       per recipient. This is especially important for post-quantum
       readiness, where KEM operations involve larger keys. autoOpen
       transparently dispatches between direct and group decryption, so
       the calling code doesn't need to track which mode was used.

   10. Call clearCaches() when switching user contexts or after long idle periods.

       The KeyCache and GekCache store public keys and unwrapped GEKs in
       memory. If your application allows switching between user accounts
       (e.g. multi-account support), call clearCaches() when switching to
       prevent stale keys from one session leaking into another. For long-
       lived tabs, periodic cache clearing ensures keys are re-fetched and
       TOFU-verified, catching any key rotations that occurred while idle.


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
