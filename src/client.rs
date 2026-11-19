//! Xmip's side: the calls a Location and an archive make, each one signed
//! request over one connection.
//!
//! Path-style addressing — `/bucket/key` at one endpoint — because it is
//! what every S3-compatible store speaks and what a private endpoint
//! without wildcard DNS can serve; virtual-hosted style is the same request
//! with the bucket moved into the host.
//!
//! A receive's get and delete hold to the `ETag` the listing gave
//! (`If-Match`), and an archive's put writes only where nothing is
//! (`If-None-Match: *`), so neither reads, deletes nor writes over an
//! object written since. What S3 answers a condition is read from the
//! status before the answer is judged: AWS, *`GetObject`*, *`DeleteObject`*
//! and *`PutObject`* (docs.aws.amazon.com/AmazonS3/latest/API/
//! `API_GetObject.html`, `API_DeleteObject.html`, `API_PutObject.html`), and
//! *How to perform conditional deletes* (docs.aws.amazon.com/AmazonS3/
//! latest/userguide/conditional-deletes.html), which general purpose
//! buckets take since 2025-09-16 (aws.amazon.com/about-aws/whats-new/
//! 2025/09/amazon-s3-conditional-deletes-s3-general-purpose-buckets).

use std::time::Duration;

use transport::error::Result;
use transport::listed::AsListed;

use aws::sigv4::{self, Signer};
use codec::percent::encode;
use http::endpoint::{Connections, Offer};
use http::status;
use net::Endpoint;
use net::http::{Request, Response};

/// The signer both ends of S3 sign and verify with: the `s3` scope, and
/// the payload hash carried in `x-amz-content-sha256`, which S3 asks for.
#[must_use]
pub fn signer(region: &str, access_key: &str, secret_key: &str) -> Signer {
    Signer::new("s3", region, access_key, secret_key).hashing_payload_in_header()
}

pub struct Client {
    endpoint: Endpoint,
    signer: Signer,
    timeout: Option<Duration>,
    /// The connections kept to the service, shared with the transport
    /// that made this client.
    connections: Connections,
}

impl Client {
    /// Speak to the S3 endpoint at `endpoint` — `http://host:port` or
    /// `https://host:port` — in `region`, as `access_key`.
    ///
    /// # Errors
    /// Where `endpoint` is not an HTTP URL.
    pub fn new(endpoint: &str, region: &str, access_key: &str, secret_key: &str) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::parse(endpoint)?,
            signer: signer(region, access_key, secret_key),
            timeout: None,
            connections: Connections::new(),
        })
    }

    /// Give up on an endpoint that stops answering after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Keep connections among `connections`, which the transport holds
    /// across every client it makes.
    #[must_use]
    pub fn sharing(mut self, connections: Connections) -> Self {
        self.connections = connections;
        self
    }

    /// The keys under `prefix` in `bucket`, each with its `ETag`, as many
    /// as one listing carries — a thousand — so a fuller prefix is taken a
    /// thousand at a time.
    ///
    /// # Errors
    /// Where the endpoint refused, could not be reached, or did not answer
    /// with a listing naming each key's `ETag`.
    pub fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<(String, String)>> {
        let request = Request::new("GET", format!("/{}", encode(bucket, false)))
            .query("list-type", "2")
            .query("prefix", prefix);
        crate::xml::OBJECTS.objects(self.call(request)?.text()?)
    }

    /// The object at `key` in `bucket`, or `None` where there is none.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn get(&self, bucket: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let answer = self.answer(Request::new("GET", object(bucket, key)))?;
        if answer.status == NOT_FOUND {
            return Ok(None);
        }
        judge(answer).map(|held| Some(held.body))
    }

    /// The object at `key` in `bucket` while it bears `etag`, the `ETag` a
    /// listing gave it: `GET` with `If-Match`, which S3 answers 412 where
    /// the object was written since and 404 where it was deleted, both
    /// [`AsListed::Changed`] (`API_GetObject.html`).
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn get_as_listed(&self, bucket: &str, key: &str, etag: &str) -> Result<AsListed<Vec<u8>>> {
        let request = Request::new("GET", object(bucket, key)).header("If-Match", etag);
        Ok(match as_listed(self.answer(request)?, READ_CHANGED)? {
            AsListed::Held(answer) => AsListed::Held(answer.body),
            AsListed::Changed => AsListed::Changed,
        })
    }

    /// Delete the object at `key` in `bucket` while it bears `etag`, the
    /// `ETag` a listing gave it: `DELETE` with `If-Match`. S3 answers 412
    /// where the object was written since, 404 where a delete got there
    /// first and 409 where a `PUT` or `DELETE` completed while this one
    /// was being judged, each [`AsListed::Changed`], with nothing deleted
    /// (`conditional-deletes.html`). The condition asks for `s3:GetObject`
    /// beside `s3:DeleteObject`.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn delete_as_listed(&self, bucket: &str, key: &str, etag: &str) -> Result<AsListed<()>> {
        let request = Request::new("DELETE", object(bucket, key)).header("If-Match", etag);
        Ok(match as_listed(self.answer(request)?, DELETE_CHANGED)? {
            AsListed::Held(_) => AsListed::Held(()),
            AsListed::Changed => AsListed::Changed,
        })
    }

    /// Store `bytes` as the object at `key` in `bucket`, over whatever is
    /// there: a Send Location's put.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn put(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<()> {
        self.call(stored(bucket, key, bytes)).map(|_| ())
    }

    /// Store `bytes` as the object at `key` in `bucket` where no object is
    /// there, and say whether it was stored: `PUT` with `If-None-Match: *`,
    /// which S3 answers 412 where an object is there already, and nothing
    /// is written over (`API_PutObject.html`). A 409
    /// `ConditionalRequestConflict` is a write that completed while this
    /// one was being judged; AWS says retry the upload, and it is retried
    /// once, against what that write left. A second 409 is a failure worth
    /// repeating.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn put_new(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<bool> {
        let new = || stored(bucket, key, bytes).header("If-None-Match", "*");
        let answer = self.answer(new())?;
        let answer = if answer.status == CONFLICT {
            self.answer(new())?
        } else {
            answer
        };
        created(answer)
    }

    fn call(&self, request: Request) -> Result<Response> {
        judge(self.answer(request)?)
    }

    /// What the endpoint answered `request`, signed, with its status not
    /// yet judged: a condition's answer is read from it first.
    fn answer(&self, request: Request) -> Result<Response> {
        let signed = self.signer.sign(
            request.header("Host", &self.endpoint.authority()),
            &sigv4::now(),
        );
        self.connections
            .exchange(&self.endpoint, self.timeout, Offer::Http11, &signed)
    }
}

/// No such object, or no longer.
const NOT_FOUND: u16 = 404;
/// A write or a delete completed while a conditional one was judged.
const CONFLICT: u16 = 409;
/// The condition did not hold.
const PRECONDITION_FAILED: u16 = 412;
/// What a `GET` held to an `ETag` answers when the object is not the one
/// listed.
const READ_CHANGED: &[u16] = &[PRECONDITION_FAILED, NOT_FOUND];
/// What a `DELETE` held to an `ETag` answers when the object is not the
/// one listed.
const DELETE_CHANGED: &[u16] = &[PRECONDITION_FAILED, NOT_FOUND, CONFLICT];

fn object(bucket: &str, key: &str) -> String {
    format!("/{}/{}", encode(bucket, false), encode(key, true))
}

/// The `PUT` storing `bytes` as the object at `key` in `bucket`.
fn stored(bucket: &str, key: &str, bytes: &[u8]) -> Request {
    Request::new("PUT", object(bucket, key))
        .header("Content-Type", "application/octet-stream")
        .body(bytes)
}

/// The answer to a request held to a listed `ETag`: [`AsListed::Changed`]
/// where its status is one of `changed`, otherwise judged.
fn as_listed(answer: Response, changed: &[u16]) -> Result<AsListed<Response>> {
    if changed.contains(&answer.status) {
        return Ok(AsListed::Changed);
    }
    judge(answer).map(AsListed::Held)
}

/// Whether a `PUT` with `If-None-Match: *` stored its object: not where
/// one was there already, otherwise judged.
fn created(answer: Response) -> Result<bool> {
    if answer.status == PRECONDITION_FAILED {
        return Ok(false);
    }
    judge(answer).map(|_| true)
}

/// A 2xx answer as it is; anything else as a failure naming the status and
/// the code S3 put in the body, retryable where HTTP or S3 says come back:
/// `SlowDown`, and `ConditionalRequestConflict`, which AWS says to retry.
fn judge(response: Response) -> Result<Response> {
    status::judge(
        "S3",
        response,
        |answer| {
            answer
                .text()
                .ok()
                .and_then(|xml| codec::xml::text(xml, "Code").ok().flatten())
                .unwrap_or_default()
        },
        |code| code == "SlowDown" || code == "ConditionalRequestConflict",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Event, Session};
    use std::assert_matches;
    use transport::socket;

    /// A session answering `requests` signed requests on its own thread,
    /// and a client signing as it expects.
    fn both_ends(requests: usize) -> (Client, std::thread::JoinHandle<(Session, Vec<Event>)>) {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = std::thread::spawn(move || {
            let mut session = Session::new("eu-north-1", "AKID", "secret")
                .timing_out_after(Duration::from_secs(2));
            let events: Vec<Event> = (0..requests)
                .map(|_| session.serve_one(&listener).expect("served"))
                .collect();
            (session, events)
        });
        let client = Client::new(&format!("http://{address}"), "eu-north-1", "AKID", "secret")
            .expect("endpoint")
            .timing_out_after(Duration::from_secs(2));
        (client, far_end)
    }

    /// What a request held to an `ETag` said, `None` where S3 answered it
    /// changed, in a shape a test compares.
    fn held<T>(said: Result<AsListed<T>>) -> Result<Option<T>> {
        said.map(|said| match said {
            AsListed::Held(it) => Some(it),
            AsListed::Changed => None,
        })
    }

    #[test]
    fn the_calls_reach_a_session_and_come_back_shaped_as_s3_shapes_them() {
        let (client, far_end) = both_ends(7);
        client.put("orders", "in/a b.edi", b"UNA").expect("put");
        client.put("orders", "out/c.edi", b"UNB").expect("put");
        let listed = client.list("orders", "in/").expect("list");
        assert_eq!(
            listed,
            vec![("in/a b.edi".to_string(), "\"1\"".to_string())],
            "the first object written"
        );
        let tag = &listed[0].1;
        assert_eq!(
            client.get("orders", "in/a b.edi").expect("get"),
            Some(b"UNA".to_vec())
        );
        let read = held(client.get_as_listed("orders", "in/a b.edi", tag));
        assert_eq!(read.expect("get"), Some(b"UNA".to_vec()));
        let deleted = held(client.delete_as_listed("orders", "in/a b.edi", tag));
        assert_eq!(deleted.expect("delete"), Some(()));
        assert_eq!(client.get("orders", "in/a b.edi").expect("get"), None);
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(session.objects().len(), 1);
        assert_matches!(&events[2], Event::Listed { prefix, .. } if prefix == "in/");
        assert_eq!(
            events[3..5],
            [
                Event::Retrieved("aws-s3://orders/in/a b.edi".to_string()),
                Event::Retrieved("aws-s3://orders/in/a b.edi".to_string())
            ]
        );
        assert_eq!(
            events[5],
            Event::Deleted("aws-s3://orders/in/a b.edi".to_string())
        );
        assert_eq!(events[6], Event::Refused("NoSuchKey".to_string()));
    }

    #[test]
    fn a_get_or_delete_held_to_a_stale_etag_finds_it_changed_and_a_new_put_finds_it_there() {
        let (client, far_end) = both_ends(7);
        client.put("orders", "in/a.edi", b"first").expect("put");
        client
            .put("orders", "in/a.edi", b"second")
            .expect("written again");
        let stale = "\"1\"";
        let read = held(client.get_as_listed("orders", "in/a.edi", stale));
        assert_eq!(read.expect("get"), None, "written again");
        let deleted = held(client.delete_as_listed("orders", "in/a.edi", stale));
        assert_eq!(deleted.expect("delete"), None, "written again");
        assert!(!client.put_new("orders", "in/a.edi", b"third").expect("put"));
        let read = held(client.get_as_listed("orders", "in/none.edi", stale));
        assert_eq!(read.expect("get"), None, "gone");
        assert!(client.put_new("orders", "in/b.edi", b"new").expect("put"));
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(
            session.objects().get("orders/in/a.edi"),
            Some(&b"second".to_vec()),
            "nothing read, deleted or written over"
        );
        assert_eq!(
            events[2..6],
            [
                Event::Refused("PreconditionFailed".to_string()),
                Event::Refused("PreconditionFailed".to_string()),
                Event::Refused("PreconditionFailed".to_string()),
                Event::Refused("NoSuchKey".to_string())
            ]
        );
    }

    #[test]
    fn a_412_404_or_409_is_changed_as_s3_documents_each_and_a_new_put_412_is_there() {
        let said = |status, changed| {
            held(as_listed(Response::new(status), changed)).map(|it| it.map(|a| a.status))
        };
        let read = |status| said(status, READ_CHANGED);
        let delete = |status| said(status, DELETE_CHANGED);
        assert_eq!(read(412).expect("412"), None);
        assert_eq!(read(404).expect("404"), None);
        assert_eq!(read(200).expect("200"), Some(200));
        assert!(read(409).is_err(), "a GET is not documented to answer 409");
        assert_eq!(delete(412).expect("412"), None);
        assert_eq!(delete(404).expect("404"), None);
        assert_eq!(delete(409).expect("409"), None);
        assert_eq!(delete(204).expect("204"), Some(204));
        assert!(delete(503).expect_err("server").retryable);
        assert!(!delete(403).expect_err("forbidden").retryable);
        assert_matches!(created(Response::new(412)), Ok(false));
        assert_matches!(created(Response::new(200)), Ok(true));
        let conflict =
            Response::new(409).body(crate::xml::error("ConditionalRequestConflict", "").as_bytes());
        let failure = created(conflict).expect_err("conflict");
        assert!(failure.retryable, "AWS says retry the upload: {failure}");
    }

    #[test]
    fn a_new_put_meeting_a_conflict_is_sent_once_more() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = std::thread::spawn(move || {
            let clock = std::sync::Arc::new(xcore::SystemClock);
            [409, 200].map(|status| {
                http::server::serve_one(
                    &listener,
                    Some(Duration::from_secs(2)),
                    clock.clone(),
                    |r| {
                        let conflict = crate::xml::error("ConditionalRequestConflict", "");
                        let answer = Response::new(status);
                        let answer = if status == 409 {
                            answer.body(conflict.as_bytes())
                        } else {
                            answer
                        };
                        (r.header_value("If-None-Match").map(str::to_string), answer)
                    },
                )
                .expect("served")
            })
        });
        let client = Client::new(&format!("http://{address}"), "eu-north-1", "AKID", "secret")
            .expect("endpoint")
            .timing_out_after(Duration::from_secs(2));
        assert!(client.put_new("orders", "a.edi", b"x").expect("stored"));
        let conditions = far_end.join().expect("thread");
        assert_eq!(conditions, [Some("*".to_string()), Some("*".to_string())]);
    }

    #[test]
    fn a_server_failure_is_worth_repeating_and_a_client_one_is_not() {
        assert!(judge(Response::new(503)).expect_err("server").retryable);
        assert!(judge(Response::new(429)).expect_err("throttled").retryable);
        let slow = Response::new(400).body(crate::xml::error("SlowDown", "").as_bytes());
        assert!(judge(slow).expect_err("slow down").retryable);
        assert!(!judge(Response::new(403)).expect_err("forbidden").retryable);
        assert!(Client::new("orders.local", "r", "a", "s").is_err());
    }
}
