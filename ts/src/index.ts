import wasmInit, {
  VeilClient,
  StreamSealer as WasmStreamSealer,
  StreamOpener as WasmStreamOpener,
} from "veil";
import type { InitInput } from "veil";
import { VeilError } from "./types.js";
import type {
  Envelope,
  AuditEntry,
  EnvelopeMetadata,
  GroupKeyBundle,
  StreamHeader,
  SealResult,
} from "./types.js";

export type {
  Envelope,
  WrappedKey,
  AuditEntry,
  EnvelopeMetadata,
  GroupKeyBundle,
  StreamHeader,
  SealResult,
} from "./types.js";
export { VeilError } from "./types.js";
export type { InitInput };

/** Initialize the WASM module. Must be called once before using Veil. */
export async function initWasm(
  moduleOrPath?: InitInput | Promise<InitInput>,
): Promise<void> {
  await wasmInit(moduleOrPath);
}

function toJson(envelopeOrJson: Envelope | string): string {
  return typeof envelopeOrJson === "string"
    ? envelopeOrJson
    : JSON.stringify(envelopeOrJson);
}

function validateId(id: string, label: string): void {
  if (!id || typeof id !== "string") {
    throw new VeilError(`${label} must be a non-empty string`);
  }
}

function validateIds(ids: string[], label: string): void {
  if (!Array.isArray(ids)) {
    throw new VeilError(`${label} must be an array`);
  }
  for (const id of ids) {
    validateId(id, label);
  }
}

function validateTimestamp(ts: number): void {
  if (typeof ts !== "number" || !Number.isFinite(ts) || ts < 0) {
    throw new VeilError(
      "timestamp must be a non-negative finite number",
    );
  }
}

/**
 * Lightweight runtime check that a parsed JSON value has the expected keys.
 * Throws VeilError if any required field is missing or has the wrong type.
 */
function assertHasFields(
  value: unknown,
  label: string,
  fields: [string, string][], // [fieldName, expectedType]
): void {
  if (typeof value !== "object" || value === null) {
    throw new VeilError(`${label}: expected object, got ${typeof value}`);
  }
  const obj = value as Record<string, unknown>;
  for (const [field, type] of fields) {
    if (!(field in obj)) {
      throw new VeilError(`${label}: missing required field '${field}'`);
    }
    if (typeof obj[field] !== type) {
      throw new VeilError(
        `${label}: field '${field}' expected ${type}, got ${typeof obj[field]}`,
      );
    }
  }
}

const ENVELOPE_SHAPE: [string, string][] = [
  ["version", "number"],
  ["ciphertext", "string"],
];

const GROUP_BUNDLE_SHAPE: [string, string][] = [
  ["version", "number"],
  ["group_id", "string"],
  ["epoch", "number"],
  ["signer_id", "string"],
  ["signature", "string"],
];

const AUDIT_ENTRY_SHAPE: [string, string][] = [
  ["action", "string"],
  ["actor_id", "string"],
  ["timestamp", "number"],
  ["entry_hash", "string"],
  ["signature", "string"],
];

const STREAM_HEADER_SHAPE: [string, string][] = [
  ["version", "number"],
  ["chunk_size", "number"],
  ["nonce_prefix", "string"],
];

function validateMetadata(meta: EnvelopeMetadata | undefined): string | undefined {
  if (meta === undefined || meta === null) return undefined;
  try {
    return JSON.stringify(meta);
  } catch {
    throw new VeilError("metadata must be JSON-serializable");
  }
}

/**
 * Safety net for WASM memory cleanup. If the caller forgets to call `free()`,
 * the FinalizationRegistry will release the WASM object when the JS wrapper
 * is garbage collected. Explicit `free()` is still preferred for deterministic
 * cleanup; this only guards against leaks.
 */
const wasmRegistry = new FinalizationRegistry<{ free(): void }>((ref) => {
  try {
    ref.free();
  } catch {
    // Already freed or WASM module unloaded — ignore
  }
});

/** Streaming sealer — encrypts data chunk by chunk. */
export class VeilStreamSealer {
  /** @internal */
  constructor(private readonly inner: WasmStreamSealer) {
    wasmRegistry.register(this, inner, inner);
  }

  /** Get the stream header (send/store before chunks). */
  header(): StreamHeader {
    try {
      const header: StreamHeader = JSON.parse(this.inner.header());
      assertHasFields(header, "StreamHeader", STREAM_HEADER_SHAPE);
      return header;
    } catch (e) {
      throw new VeilError("Failed to get stream header", e);
    }
  }

  /** Get the stream header as a JSON string. */
  headerJson(): string {
    try {
      return this.inner.header();
    } catch (e) {
      throw new VeilError("Failed to get stream header", e);
    }
  }

  /** Encrypt a chunk. Set `isLast` to true for the final chunk. */
  sealChunk(chunk: Uint8Array, isLast: boolean): Uint8Array {
    try {
      return this.inner.sealChunk(chunk, isLast);
    } catch (e) {
      throw new VeilError("Failed to seal chunk", e);
    }
  }

  /** Release WASM memory. Call when done sealing. */
  free(): void {
    wasmRegistry.unregister(this.inner);
    this.inner.free();
  }
}

/** Streaming opener — decrypts data chunk by chunk. */
export class VeilStreamOpener {
  /** @internal */
  constructor(private readonly inner: WasmStreamOpener) {
    wasmRegistry.register(this, inner, inner);
  }

  /** Decrypt a chunk. Returns the plaintext bytes. */
  openChunk(encryptedChunk: Uint8Array): Uint8Array {
    try {
      return this.inner.openChunk(encryptedChunk);
    } catch (e) {
      throw new VeilError("Failed to open chunk", e);
    }
  }

  /** Whether the final chunk has been processed. */
  isDone(): boolean {
    return this.inner.isDone();
  }

  /** Release WASM memory. Call when done opening. */
  free(): void {
    wasmRegistry.unregister(this.inner);
    this.inner.free();
  }
}

/**
 * Typed wrapper around the Veil WASM SDK.
 *
 * ```ts
 * import { initWasm, Veil } from "@veil/client";
 * await initWasm();
 * const alice = await Veil.init("alice", "https://example.com", token);
 * const { envelope } = await alice.seal("hello", ["bob"]);
 * ```
 */
export class Veil {
  private constructor(private readonly inner: VeilClient) {
    wasmRegistry.register(this, inner, inner);
  }

  // ---- Static constructors ----

  /** Initialize a Veil client. Generates or loads identity keys. */
  static async init(
    userId: string,
    serverUrl: string,
    authToken?: string | null,
  ): Promise<Veil> {
    try {
      const client = await VeilClient.init(
        userId,
        serverUrl,
        authToken ?? undefined,
      );
      return new Veil(client);
    } catch (e) {
      throw new VeilError("Failed to initialize Veil client", e);
    }
  }

  /** Import identity from an encrypted backup blob. */
  static async importIdentity(
    userId: string,
    serverUrl: string,
    blobB64: string,
    password: string,
    authToken?: string | null,
  ): Promise<Veil> {
    try {
      const client = await VeilClient.importIdentity(
        userId,
        serverUrl,
        blobB64,
        password,
        authToken ?? undefined,
      );
      return new Veil(client);
    } catch (e) {
      throw new VeilError("Failed to import identity", e);
    }
  }

  /**
   * Rotate identity keys. Generates new X25519 + Ed25519 key pairs,
   * overwrites storage, and uploads new public keys to the server.
   * Returns a new client; the old one is stale.
   *
   * Recipients must call `trustKey(userId)` to accept the new keys.
   * Use `reseal()` on existing envelopes to re-wrap with the new identity.
   */
  static async rotateKey(
    userId: string,
    serverUrl: string,
    authToken?: string | null,
  ): Promise<Veil> {
    try {
      const client = await VeilClient.rotateKey(
        userId,
        serverUrl,
        authToken ?? undefined,
      );
      return new Veil(client);
    } catch (e) {
      throw new VeilError("Failed to rotate key", e);
    }
  }

  // ---- Accessors ----

  get userId(): string {
    return this.inner.userId();
  }

  get publicKey(): string {
    return this.inner.publicKey();
  }

  get signingKey(): string {
    return this.inner.signingKey();
  }

  get isNewIdentity(): boolean {
    return this.inner.isNewIdentity();
  }

  get wasRotated(): boolean {
    return this.inner.wasRotated();
  }

  // ---- Envelope operations ----

  /** Seal data for recipients. Returns typed Envelope + raw JSON. */
  async seal(
    plaintext: string,
    recipientIds: string[],
    metadata?: EnvelopeMetadata,
  ): Promise<SealResult> {
    validateIds(recipientIds, "recipientIds");
    const metaJson = validateMetadata(metadata);
    try {
      const json = await this.inner.seal(
        plaintext,
        recipientIds,
        metaJson ?? null,
      );
      const envelope: Envelope = JSON.parse(json);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return { envelope, json };
    } catch (e) {
      throw new VeilError("Failed to seal", e);
    }
  }

  /** Seal binary data for recipients. Like `seal()` but accepts raw bytes. */
  async sealBytes(
    plaintext: Uint8Array,
    recipientIds: string[],
    metadata?: EnvelopeMetadata,
  ): Promise<SealResult> {
    validateIds(recipientIds, "recipientIds");
    const metaJson = validateMetadata(metadata);
    try {
      const json = await this.inner.sealBytes(
        plaintext,
        recipientIds,
        metaJson ?? null,
      );
      const envelope: Envelope = JSON.parse(json);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return { envelope, json };
    } catch (e) {
      throw new VeilError("Failed to seal bytes", e);
    }
  }

  /** Open an envelope. Verifies the signature first, then decrypts. */
  async open(envelopeOrJson: Envelope | string): Promise<string> {
    try {
      return await this.inner.open(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Failed to open envelope", e);
    }
  }

  /** Open an envelope and return raw bytes (no UTF-8 requirement). */
  async openBytes(envelopeOrJson: Envelope | string): Promise<Uint8Array> {
    try {
      return await this.inner.openBytes(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Failed to open envelope", e);
    }
  }

  /**
   * Open an envelope **without** verifying the signature.
   *
   * **Security warning:** A console warning is emitted when called.
   * Intended for advanced scenarios where the caller has already verified
   * the signature or intentionally wants to skip verification
   * (e.g. offline/cached envelopes).
   */
  openUnverified(envelopeOrJson: Envelope | string): string {
    try {
      return this.inner.openUnverified(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Failed to open envelope", e);
    }
  }

  /**
   * Open an envelope as raw bytes **without** verifying the signature.
   *
   * **Security warning:** A console warning is emitted when called.
   * See `openUnverified` for details.
   */
  openUnverifiedBytes(envelopeOrJson: Envelope | string): Uint8Array {
    try {
      return this.inner.openUnverifiedBytes(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Failed to open envelope", e);
    }
  }

  /** Verify the Ed25519 signature on an envelope. */
  async verify(envelopeOrJson: Envelope | string): Promise<void> {
    try {
      await this.inner.verify(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Signature verification failed", e);
    }
  }

  /** Add a recipient to an envelope. */
  async addRecipient(
    envelopeOrJson: Envelope | string,
    recipientId: string,
  ): Promise<Envelope> {
    validateId(recipientId, "recipientId");
    try {
      const result = await this.inner.addRecipient(
        toJson(envelopeOrJson),
        recipientId,
      );
      const envelope: Envelope = JSON.parse(result);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return envelope;
    } catch (e) {
      throw new VeilError("Failed to add recipient", e);
    }
  }

  /** Remove a recipient (soft revocation). */
  removeRecipient(
    envelopeOrJson: Envelope | string,
    recipientId: string,
  ): Envelope {
    validateId(recipientId, "recipientId");
    try {
      const result = this.inner.removeRecipient(
        toJson(envelopeOrJson),
        recipientId,
      );
      const envelope: Envelope = JSON.parse(result);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return envelope;
    } catch (e) {
      throw new VeilError("Failed to remove recipient", e);
    }
  }

  /** Re-seal with a fresh DEK (hard revocation). */
  async reseal(
    envelopeOrJson: Envelope | string,
    recipientIds: string[],
    metadata?: EnvelopeMetadata,
  ): Promise<SealResult> {
    validateIds(recipientIds, "recipientIds");
    const metaJson = validateMetadata(metadata);
    try {
      const json = await this.inner.reseal(
        toJson(envelopeOrJson),
        recipientIds,
        metaJson ?? null,
      );
      const envelope: Envelope = JSON.parse(json);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return { envelope, json };
    } catch (e) {
      throw new VeilError("Failed to reseal", e);
    }
  }

  // ---- Group keys ----

  /** Create a new group. Generates a GEK, wraps for members, uploads. */
  async createGroup(
    groupId: string,
    memberIds: string[],
  ): Promise<GroupKeyBundle> {
    validateId(groupId, "groupId");
    validateIds(memberIds, "memberIds");
    try {
      const json = await this.inner.createGroup(groupId, memberIds);
      const bundle: GroupKeyBundle = JSON.parse(json);
      assertHasFields(bundle, "GroupKeyBundle", GROUP_BUNDLE_SHAPE);
      return bundle;
    } catch (e) {
      throw new VeilError("Failed to create group", e);
    }
  }

  /** Add a member to a group. Returns updated bundle. */
  async addGroupMember(
    groupId: string,
    memberId: string,
  ): Promise<GroupKeyBundle> {
    validateId(groupId, "groupId");
    validateId(memberId, "memberId");
    try {
      const json = await this.inner.addGroupMember(groupId, memberId);
      const bundle: GroupKeyBundle = JSON.parse(json);
      assertHasFields(bundle, "GroupKeyBundle", GROUP_BUNDLE_SHAPE);
      return bundle;
    } catch (e) {
      throw new VeilError("Failed to add group member", e);
    }
  }

  /** Remove a member from a group (rotates GEK). Returns updated bundle. */
  async removeGroupMember(
    groupId: string,
    memberId: string,
  ): Promise<GroupKeyBundle> {
    validateId(groupId, "groupId");
    validateId(memberId, "memberId");
    try {
      const json = await this.inner.removeGroupMember(groupId, memberId);
      const bundle: GroupKeyBundle = JSON.parse(json);
      assertHasFields(bundle, "GroupKeyBundle", GROUP_BUNDLE_SHAPE);
      return bundle;
    } catch (e) {
      throw new VeilError("Failed to remove group member", e);
    }
  }

  /** Seal data for a group. Returns typed Envelope + raw JSON. */
  async groupSeal(
    plaintext: string,
    groupId: string,
    metadata?: EnvelopeMetadata,
  ): Promise<SealResult> {
    validateId(groupId, "groupId");
    const metaJson = validateMetadata(metadata);
    try {
      const json = await this.inner.groupSeal(
        plaintext,
        groupId,
        metaJson ?? null,
      );
      const envelope: Envelope = JSON.parse(json);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return { envelope, json };
    } catch (e) {
      throw new VeilError("Failed to group seal", e);
    }
  }

  /** Open a group envelope. Returns the plaintext. */
  async groupOpen(envelopeOrJson: Envelope | string): Promise<string> {
    try {
      return await this.inner.groupOpen(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Failed to open group envelope", e);
    }
  }

  // ---- Auto-group ----

  /** Seal data using an auto-managed group (deterministic group ID from participants). */
  async autoSeal(
    plaintext: string,
    recipientIds: string[],
    metadata?: EnvelopeMetadata,
  ): Promise<SealResult> {
    validateIds(recipientIds, "recipientIds");
    const metaJson = validateMetadata(metadata);
    try {
      const json = await this.inner.autoSeal(
        plaintext,
        recipientIds,
        metaJson ?? null,
      );
      const envelope: Envelope = JSON.parse(json);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return { envelope, json };
    } catch (e) {
      throw new VeilError("Failed to auto seal", e);
    }
  }

  /** Open any envelope (direct or group) transparently. Verifies signatures. */
  async autoOpen(envelopeOrJson: Envelope | string): Promise<string> {
    try {
      return await this.inner.autoOpen(toJson(envelopeOrJson));
    } catch (e) {
      throw new VeilError("Failed to auto open", e);
    }
  }

  // ---- Cache management ----

  /** Invalidate the cached GEK for a group (e.g. after membership changes). */
  invalidateGroupCache(groupId: string): void {
    validateId(groupId, "groupId");
    try {
      this.inner.invalidateGroupCache(groupId);
    } catch (e) {
      throw new VeilError("Failed to invalidate group cache", e);
    }
  }

  /** Clear all in-memory caches (key directory + GEK). */
  clearCaches(): void {
    try {
      this.inner.clearCaches();
    } catch (e) {
      throw new VeilError("Failed to clear caches", e);
    }
  }

  // ---- Streaming ----

  /** Verify the Ed25519 signature on a stream header. */
  async verifyStreamHeader(
    headerOrJson: StreamHeader | string,
  ): Promise<void> {
    try {
      const json =
        typeof headerOrJson === "string"
          ? headerOrJson
          : JSON.stringify(headerOrJson);
      await this.inner.verifyStreamHeader(json);
    } catch (e) {
      throw new VeilError("Stream header verification failed", e);
    }
  }

  /** Initialize a streaming sealer for per-recipient encryption. */
  async sealStreamInit(
    recipientIds: string[],
    metadata?: EnvelopeMetadata,
    chunkSize?: number,
  ): Promise<VeilStreamSealer> {
    validateIds(recipientIds, "recipientIds");
    const metaJson = validateMetadata(metadata);
    try {
      const sealer = await this.inner.sealStreamInit(
        recipientIds,
        metaJson ?? null,
        chunkSize ?? null,
      );
      return new VeilStreamSealer(sealer);
    } catch (e) {
      throw new VeilError("Failed to init stream sealer", e);
    }
  }

  /** Initialize a streaming opener. Verifies the header signature first. */
  async openStreamInit(
    headerOrJson: StreamHeader | string,
  ): Promise<VeilStreamOpener> {
    try {
      const json =
        typeof headerOrJson === "string"
          ? headerOrJson
          : JSON.stringify(headerOrJson);
      const opener = await this.inner.openStreamInit(json);
      return new VeilStreamOpener(opener);
    } catch (e) {
      throw new VeilError("Failed to init stream opener", e);
    }
  }

  /**
   * Initialize a streaming opener **without** verifying the header signature.
   *
   * **Security warning:** A console warning is emitted when called.
   * Intended for advanced scenarios where the caller has already verified
   * the header or intentionally wants to skip verification.
   */
  openStreamInitUnverified(
    headerOrJson: StreamHeader | string,
  ): VeilStreamOpener {
    try {
      const json =
        typeof headerOrJson === "string"
          ? headerOrJson
          : JSON.stringify(headerOrJson);
      const opener = this.inner.openStreamInitUnverified(json);
      return new VeilStreamOpener(opener);
    } catch (e) {
      throw new VeilError("Failed to init stream opener", e);
    }
  }

  /** Initialize a streaming sealer for group encryption. */
  async groupSealStreamInit(
    groupId: string,
    metadata?: EnvelopeMetadata,
    chunkSize?: number,
  ): Promise<VeilStreamSealer> {
    validateId(groupId, "groupId");
    const metaJson = validateMetadata(metadata);
    try {
      const sealer = await this.inner.groupSealStreamInit(
        groupId,
        metaJson ?? null,
        chunkSize ?? null,
      );
      return new VeilStreamSealer(sealer);
    } catch (e) {
      throw new VeilError("Failed to init group stream sealer", e);
    }
  }

  /** Initialize a streaming opener for a group stream. */
  async groupOpenStreamInit(
    headerOrJson: StreamHeader | string,
  ): Promise<VeilStreamOpener> {
    try {
      const json =
        typeof headerOrJson === "string"
          ? headerOrJson
          : JSON.stringify(headerOrJson);
      const opener = await this.inner.groupOpenStreamInit(json);
      return new VeilStreamOpener(opener);
    } catch (e) {
      throw new VeilError("Failed to init group stream opener", e);
    }
  }

  // ---- Identity ----

  /** Export identity keys encrypted with a password (min 16 chars). */
  exportIdentity(password: string): string {
    try {
      return this.inner.exportIdentity(password);
    } catch (e) {
      throw new VeilError("Failed to export identity", e);
    }
  }

  /**
   * Clear TOFU pins for a user (accept their new keys after rotation).
   *
   * **Security note:** This is a sensitive operation. Applications should
   * implement their own rate limiting or confirmation UI (e.g. a dialog
   * or re-authentication) before allowing `trustKey()` calls.
   */
  trustKey(userId: string): void {
    validateId(userId, "userId");
    try {
      this.inner.trustKey(userId);
    } catch (e) {
      throw new VeilError("Failed to trust key", e);
    }
  }

  // ---- Audit ----

  /**
   * Create a signed audit log entry.
   *
   * **Note:** The `timestamp` is caller-provided and cannot be verified
   * by the SDK. A malicious client can set arbitrary timestamps.
   * The timestamp IS included in the signed payload, so it cannot be
   * altered after creation.
   */
  createAuditEntry(
    action: string,
    targetId: string | null,
    timestamp: number,
    prevHash?: string | null,
  ): AuditEntry {
    validateId(action, "action");
    if (targetId != null) validateId(targetId, "targetId");
    validateTimestamp(timestamp);
    try {
      const json = this.inner.createAuditEntry(
        action,
        targetId ?? undefined,
        timestamp,
        prevHash ?? undefined,
      );
      const entry: AuditEntry = JSON.parse(json);
      assertHasFields(entry, "AuditEntry", AUDIT_ENTRY_SHAPE);
      return entry;
    } catch (e) {
      throw new VeilError("Failed to create audit entry", e);
    }
  }

  /** Anchor an audit entry to an envelope (sets audit_hash). */
  anchorAudit(
    envelopeOrJson: Envelope | string,
    entryOrJson: AuditEntry | string,
  ): Envelope {
    try {
      const entryJson =
        typeof entryOrJson === "string"
          ? entryOrJson
          : JSON.stringify(entryOrJson);
      const result = this.inner.anchorAudit(
        toJson(envelopeOrJson),
        entryJson,
      );
      const envelope: Envelope = JSON.parse(result);
      assertHasFields(envelope, "Envelope", ENVELOPE_SHAPE);
      return envelope;
    } catch (e) {
      throw new VeilError("Failed to anchor audit", e);
    }
  }

  /** Verify audit log chain + signatures + envelope anchor. */
  async verifyAuditLog(
    envelopeOrJson: Envelope | string,
    entries: AuditEntry[] | string,
  ): Promise<void> {
    try {
      const entriesJson =
        typeof entries === "string" ? entries : JSON.stringify(entries);
      await this.inner.verifyAuditLog(toJson(envelopeOrJson), entriesJson);
    } catch (e) {
      throw new VeilError("Audit log verification failed", e);
    }
  }

  // ---- Cleanup ----

  /** Release WASM memory. Call when done with this client. */
  free(): void {
    wasmRegistry.unregister(this.inner);
    this.inner.free();
  }
}
