/** A wrapped DEK for a single recipient (ECIES). */
export interface WrappedKey {
  user_id: string;
  ephemeral_public: string;
  encrypted_dek: string;
}

/** Encrypted envelope: ciphertext + per-recipient wrapped DEKs. */
export interface Envelope {
  version: number;
  ciphertext: string;
  recipients: WrappedKey[];
  metadata?: Record<string, unknown>;
  signer_id?: string;
  signature?: string;
  audit_hash?: string;
  group_id?: string;
  wrapped_dek?: string;
}

/** An audit log entry with hash-chain linkage and Ed25519 signature. */
export interface AuditEntry {
  action: string;
  actor_id: string;
  target_id?: string;
  timestamp: number;
  prev_hash: string;
  entry_hash: string;
  signature: string;
}

/** A group key bundle: GEK wrapped per-member, stored server-side. */
export interface GroupKeyBundle {
  version: number;
  group_id: string;
  epoch: number;
  members: WrappedKey[];
  signer_id: string;
  signature: string;
}

/** Stream header: DEK wrapped per-recipient or by GEK, stream metadata. */
export interface StreamHeader {
  version: number;
  chunk_size: number;
  nonce_prefix: string;
  recipients: WrappedKey[];
  metadata?: Record<string, unknown>;
  signer_id?: string;
  signature?: string;
  group_id?: string;
  wrapped_dek?: string;
}

/** Unencrypted metadata attached to an envelope. */
export type EnvelopeMetadata = Record<string, unknown>;

/** Result of a seal or reseal operation. */
export interface SealResult {
  envelope: Envelope;
  json: string;
}

/** Veil SDK error with structured cause. */
export class VeilError extends Error {
  public readonly cause: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "VeilError";
    this.cause = cause;
  }
}
