//! The bucket a Receive Location takes objects from, as the capability's
//! one object-store receive and claim reach it (`transport::listed`):
//! listed under the Location's prefix, each object got and deleted as it
//! was listed (`If-Match`), and its claim, `<key>.xmip-claim`, put only
//! where none lies (`If-None-Match: *`, ADR-0024, amendment 2026-11-20).

use std::sync::Arc;

use transport::claim::{Artifact, Claimed, ResourceClaim};
use transport::error::Result;
use transport::listed::{AsListed, Object, Store};

use crate::{Client, S3Transport, origin};

/// One bucket under one prefix, spoken to through one client.
pub struct Bucket {
    client: Client,
    /// The bucket's own name.
    named: String,
    prefix: String,
}

impl Store for Bucket {
    fn list(&self) -> Result<Vec<Object>> {
        self.client.list(&self.named, &self.prefix)
    }

    fn get(&self, key: &str, etag: &str) -> Result<AsListed<Vec<u8>>> {
        self.client.get_as_listed(&self.named, key, etag)
    }

    fn delete(&self, key: &str, etag: &str) -> Result<AsListed<()>> {
        self.client.delete_as_listed(&self.named, key, etag)
    }

    fn create(&self, key: &str, bytes: &[u8]) -> Result<Option<String>> {
        self.client.put_new(&self.named, key, bytes)
    }

    fn origin(&self, key: &str) -> String {
        origin(&self.named, key)
    }
}

impl S3Transport {
    /// The bucket this transport receives from, through a client of its
    /// own.
    ///
    /// # Errors
    /// Where the endpoint is not an HTTP URL.
    pub fn bucket(&self) -> Result<Arc<dyn Store>> {
        Ok(Arc::new(Bucket {
            client: self.client()?,
            named: self.bucket.clone(),
            prefix: self.prefix.clone(),
        }))
    }
}

/// One object claimed by its address, `aws-s3://bucket/key`, as a receive
/// claims it.
impl ResourceClaim for S3Transport {
    fn is_available(&self, artifact: &Artifact) -> Result<bool> {
        self.claims.is_available(&*self.bucket()?, artifact)
    }

    fn claim(&self, artifact: &Artifact) -> Result<Claimed> {
        self.claims.claim(&*self.bucket()?, artifact)
    }

    fn release(&self, claimed: Claimed) -> Result<()> {
        self.claims.release(&*self.bucket()?, &claimed)
    }
}
