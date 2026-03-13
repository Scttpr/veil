pub mod constants;
pub mod crypto;
pub mod keys;
pub mod envelope;
pub mod audit;
pub mod group;
pub mod stream;
pub mod key_directory;
mod storage;
mod webcrypto_shim;
mod client;

/// Test helpers for generating key material.
///
/// Available in both unit tests (`#[cfg(test)]`) and integration tests
/// (via the `test-utils` feature).
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use client::{VeilClient, StreamSealer, StreamOpener};
