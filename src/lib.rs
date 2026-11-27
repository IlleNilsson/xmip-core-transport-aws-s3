#![forbid(unsafe_code)]

//! Streams that arrive as objects in an S3 bucket. One object is one Stream,
//! its key kept beside it.
//!
//! S3 is the Party drop box of the cloud era, and every object store
//! since speaks its REST API: a bucket, keys under a prefix, four calls. A
//! Receive Location lists a prefix, gets each object as the runtime first
//! reads it, and deletes it once the runtime accepts it after the whole
//! receive cycle, both held to the `ETag` the listing gave — one refused
//! stays where it lies and is not received again while its `ETag` is
//! unchanged, one whose cycle failed stays for the next receive; a Send
//! Location puts a Stream as an object.
//! Both are Signature Version 4 over plain HTTP/1.1 on a socket —
//! `https://` with the `tls` feature, which is the http technology's TLS
//! (ADR-0033).
//!
//! ```text
//! xml.rs       the listing and the error, picked by hand
//! client.rs    Xmip's side: list, get, put, delete, each held to a condition
//!              where one is asked
//! bucket.rs    the bucket as the capability's receive and claim reach it
//! session.rs   the far end a test or the System Tests run on loopback
//! ```
//!
//! The endpoint, HTTP itself and the judgment of an answer come from the
//! http technology, the percent-encoding from `net`, Signature Version 4
//! from the AWS crate, the flat XML scan from the capability (ADR-0044). The signer
//! lived here until 2026-09-14, when aws-sqs was found importing it, and in
//! the http technology until the owner's ruling of 2026-09-22: what AWS
//! speaks is the AWS crate's to share.
//!
//! **One node receives an object** (ADR-0024, amendment 2026-11-20): a
//! receive claims each object it hands over by putting `<key>.xmip-claim`
//! beside it with `If-None-Match: *`, which S3 stores only where no object
//! of the key exists, `412 Precondition Failed` otherwise — the capability's
//! claim, written once (`transport::listed::Claims`).
//! [`Transport::claims`] answers the same claim for one object by its
//! address. On an S3-compatible endpoint that ignores
//! `If-None-Match: *` every claim's put succeeds, so two nodes may both
//! receive one object there: twice, never lost (open problem 75).
//!
//! The origin URI is the object under the scheme that chooses this
//! technology, its name: `aws-s3://bucket/in/order-1.edi`. A send target is
//! the same form, or a key alone in this transport's bucket.
//!
//! **Built with its `declaration` feature alone** the crate is
//! [`declaration`].

#[cfg(feature = "default")]
pub mod bucket;
#[cfg(feature = "default")]
pub mod client;
#[cfg(feature = "declaration")]
pub mod declaration;
#[cfg(feature = "default")]
pub mod session;
#[cfg(feature = "default")]
pub mod xml;

#[cfg(feature = "default")]
use std::net::TcpListener;
#[cfg(feature = "default")]
use std::time::Duration;

#[cfg(feature = "default")]
pub use client::Client;
#[cfg(feature = "default")]
use http::endpoint::Connections;
#[cfg(feature = "default")]
use net::{Endpoint, Target};
#[cfg(feature = "default")]
pub use session::{Event, Session};
#[cfg(feature = "default")]
use transport::error::{Result, protocol_error};
#[cfg(feature = "default")]
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
#[cfg(feature = "default")]
use transport::{ArrivalIdentity, NodeStart, claim::Claimant, listed::Claims};
#[cfg(feature = "default")]
use transport::{Arrived, Configured, Directions, ResourceClaim, Transport};
#[cfg(feature = "default")]
use transport::{listening::Listening, socket};
#[cfg(feature = "default")]
use xcore::settings::{Read, Settings};

/// What the loopback pair agrees on: one bucket, one object put there, one
/// credential in one region that the far end expects and the near end
/// signs as.
#[cfg(feature = "default")]
const LOOPBACK_BUCKET: &str = "probe";
#[cfg(feature = "default")]
const LOOPBACK_OBJECT: &str = "probe.bin";
#[cfg(feature = "default")]
const LOOPBACK_REGION: &str = "eu-north-1";
#[cfg(feature = "default")]
const LOOPBACK_ACCESS_KEY: &str = "AKIDPROBE";
#[cfg(feature = "default")]
const LOOPBACK_SECRET_KEY: &str = "probe";

#[cfg(feature = "default")]
#[derive(Clone)]
pub struct S3Transport {
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    prefix: String,
    timeout: Option<Duration>,
    /// The connections kept to the service, shared by every client this
    /// makes.
    connections: Connections,
    /// The claims this Location makes, and the objects it refused and left
    /// in the bucket, each with its `ETag`; a clone shares them.
    claims: Claims,
    /// The secret a Location names, the secret access key its requests are
    /// signed with, read at each request (ADR-0019, amendment 2026-10-29;
    /// ADR-0015, amendment 2026-11-25); `secret_key` where it names none.
    secret: Option<transport::Secured>,
}

#[cfg(feature = "default")]
impl S3Transport {
    /// Speak to the endpoint at `endpoint` — `http://host:port` or
    /// `https://host:port` — in `region`, about `bucket`.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, region: &str, bucket: &str) -> Self {
        Self {
            endpoint: endpoint.into(),
            region: region.to_string(),
            bucket: bucket.to_string(),
            access_key: String::new(),
            secret_key: String::new(),
            prefix: String::new(),
            timeout: None,
            connections: Connections::new(),
            claims: Claims::new(Claimant::process()),
            secret: None,
        }
    }

    /// Sign as this access key.
    #[must_use]
    pub fn with_credentials(mut self, access_key: &str, secret_key: &str) -> Self {
        self.access_key = access_key.to_string();
        self.secret_key = secret_key.to_string();
        self
    }

    /// Receive only what is under `prefix` — `in/`, say.
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    /// The client this transport speaks through, signing with the secret
    /// the Location names as it is set now.
    ///
    /// # Errors
    /// Where the endpoint is not an HTTP URL, or the Location's secret is
    /// not set, cannot be read or is no password
    /// (`transport::secured::presented`).
    pub fn client(&self) -> Result<Client> {
        let secret_key =
            transport::secured::presented(self.secret.as_ref(), &self.secret_key, "aws-s3")?;
        let client = Client::new(&self.endpoint, &self.region, &self.access_key, &secret_key)?;
        let client = client.sharing(self.connections.clone());
        Ok(match self.timeout {
            Some(timeout) => client.timing_out_after(timeout),
            None => client,
        })
    }

    /// A far end that holds this transport's credentials, for a test or the
    /// System Tests to run on loopback.
    #[must_use]
    pub fn session(&self) -> Session {
        let session = Session::new(&self.region, &self.access_key, &self.secret_key);
        match self.timeout {
            Some(timeout) => session.timing_out_after(timeout),
            None => session,
        }
    }

    /// Where a target names the bucket and key itself — `aws-s3://bucket/key`
    /// — or is a key alone in this transport's bucket.
    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str) {
        Target::under(Self::SCHEMES, target).map_or((&self.bucket, target), |named| {
            (named.authority(), named.path())
        })
    }
}

#[cfg(feature = "default")]
impl Transport for S3Transport {
    fn name(&self) -> &'static str {
        "aws-s3"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a receive lists again what is not yet told")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a receive lists the bucket and returns")
    }

    /// What [`transport::listed::Claims::listed`] wins under the prefix, each
    /// object's claim put with `If-None-Match: *`, its get and its delete
    /// held to the `ETag` the listing gave (`If-Match`); a `GET` body is read
    /// whole by `net::http`.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        self.claims.listed(&self.bucket()?, most)
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered(
            "Signature Version 4 signs the payload's SHA-256 before the request goes",
        )
    }

    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        let (bucket, key) = self.resolve(target);
        self.client()?.put(bucket, key, bytes)
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(self)
    }
}

#[cfg(feature = "default")]
impl Configured for S3Transport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        // The secret access key comes through the Location's secret.
        let mut transport = Self::new(address, settings.text("region"), settings.text("bucket"));
        if let Some(access_key) = settings.optional_text(aws::access_key::ACCESS_KEY_ID.name) {
            transport.access_key = access_key.to_string();
        }
        if let Some(prefix) = settings.optional_text("prefix") {
            transport = transport.with_prefix(prefix);
        }
        Ok(transport)
    }

    /// The secret access key the Location's secret holds, signed with at
    /// each request as its `access_key_id`; refused where it names none.
    fn secured_by(mut self, secret: transport::Secured) -> Result<Self> {
        let secret = aws::access_key::signing_as(&self.access_key, secret)?;
        self.secret = Some(secret);
        Ok(self)
    }

    /// The connections its clients share, an HTTP/2 one's frames in a span
    /// counted on `clock`, its node's (ADR-0068, amendment 2026-11-16).
    fn timed_by(mut self, clock: &std::sync::Arc<dyn xcore::Clock>) -> Self {
        self.connections = self.connections.timed_by(clock);
        self
    }

    /// Claims made in the name of `node`, its node and that start of it,
    /// from here on; every claim an earlier start of the node still holds
    /// in the bucket is deleted by the first receive that reaches it, and
    /// one of this start, whichever Location made it, is left (ADR-0024,
    /// amendments 2026-11-20 and 2026-11-22).
    fn on_node(mut self, node: &NodeStart) -> Result<Self> {
        self.claims = Claims::recovering(Claimant::of(node));
        Ok(self)
    }
}

/// The object `key` in `bucket`, as an origin says it, under the scheme
/// above: `aws-s3://bucket/key`. The one place the form is written: the
/// transport's receive, the session's answers and the aws-s3 archive's
/// receipt all name an object by it.
#[cfg(feature = "default")]
#[must_use]
pub fn origin(bucket: &str, key: &str) -> String {
    format!("aws-s3://{bucket}/{key}")
}

#[cfg(feature = "default")]
impl S3Transport {
    /// Both ends on this machine: an ephemeral local port, one credential
    /// the far end expects and the near end signs as, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("http://127.0.0.1:0", LOOPBACK_REGION, LOOPBACK_BUCKET)
            .with_credentials(LOOPBACK_ACCESS_KEY, LOOPBACK_SECRET_KEY)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

#[cfg(feature = "default")]
impl Loopback for S3Transport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "an object names no sender: the bucket it was taken from is in its origin",
        )
    }

    /// A bound session waiting for its one store. S3 opens a connection per
    /// call, so the session serves one request at a time until one stored.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let mut session = self.session();
        Ok(Box::new(Listening::new(
            move |listener: &TcpListener| loop {
                match session.serve_one(listener)? {
                    Event::Stored(arrived) => return Ok(arrived),
                    Event::Refused(code) => {
                        return Err(protocol_error(format!("the session refused: {code}")));
                    }
                    _ => {}
                }
            },
            socket::bind_tcp(&Endpoint::parse(&self.endpoint)?.address())?,
        )))
    }

    /// Put the payload as one object, from a fresh near end signing as
    /// this transport does, at the endpoint on `address`.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            endpoint: format!("http://{address}"),
            ..self.clone()
        };
        near.send(LOOPBACK_OBJECT, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::thread::JoinHandle;
    use transport::Taken;
    use xcore::settings::Applies;

    fn node(endpoint: &str, secret: &str) -> S3Transport {
        S3Transport::new(endpoint, "eu-north-1", "orders")
            .with_credentials("AKID", secret)
            .with_prefix("in/")
            .timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn s3_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(S3Transport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let endpoint = "https://s3.eu-north-1.amazonaws.com";
        let given = [
            text("region", "eu-north-1"),
            text("bucket", "orders"),
            text("prefix", "in/"),
            text("timeout", "5s"),
        ];
        let received = S3Transport::open(endpoint, Applies::Receive, &given).expect("built");
        assert_eq!(received.endpoint, endpoint);
        assert_eq!(
            (received.region.as_str(), received.bucket.as_str()),
            ("eu-north-1", "orders")
        );
        assert_eq!(received.prefix, "in/");
        assert_eq!(received.timeout, Some(Duration::from_secs(5)));
        assert!(
            received.secret_key.is_empty(),
            "the secret is the credentials'"
        );
        let Err(refused) = S3Transport::open(endpoint, Applies::Send, &given[..1]) else {
            panic!("the bucket is required");
        };
        assert!(refused.message.contains("\"bucket\""), "{refused}");
    }

    fn serve(
        mut session: Session,
        listener: TcpListener,
        requests: usize,
    ) -> JoinHandle<(Session, Vec<Event>)> {
        std::thread::spawn(move || {
            let events = (0..requests)
                .map(|_| session.serve_one(&listener).expect("served"))
                .collect();
            (session, events)
        })
    }

    #[test]
    fn an_object_is_got_when_read_deleted_when_accepted_and_left_when_refused_or_failed() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), "secret");
        // Three puts; a list, three claims, the one get read, its delete,
        // its claim's, the other two claims'; a list, a claim, a get, a
        // delete, its claim's; a list to see what is left.
        let far_end = serve(near.session(), listener, 18);
        near.send("in/1.edi", b"UNA:+.? '").expect("a key alone");
        near.send("aws-s3://orders/in/2.edi", b"")
            .expect("a full target");
        near.send("in/3.edi", b"third").expect("a key alone");
        let mut arrived = near.receive().expect("received");
        arrived.sort_by(|a, b| a.origin_uri.cmp(&b.origin_uri));
        assert_eq!(arrived.len(), 3);
        assert!(arrived.iter().all(Arrived::defers));
        let third = arrived.pop().expect("third");
        let second = arrived.pop().expect("second");
        assert_eq!(second.origin_uri, "aws-s3://orders/in/2.edi");
        let first = arrived.pop().expect("first").taken().expect("accepted");
        assert_eq!(first.origin_uri, "aws-s3://orders/in/1.edi");
        assert_eq!(first.bytes, b"UNA:+.? '");
        second.failed().expect("left");
        third
            .refused(transport::Refusal::Unacceptable)
            .expect("left");
        let again = near.receive().expect("received again");
        assert_eq!(again.len(), 1, "the failed one, not the refused one");
        let again = again.into_iter().next().expect("one").taken().expect("ok");
        assert_eq!(again.origin_uri, "aws-s3://orders/in/2.edi");
        assert_eq!(again.bytes, [] as [u8; 0]);
        let left = near
            .client()
            .expect("client")
            .list("orders", "in/")
            .expect("list");
        assert_eq!(
            left,
            [("in/3.edi".to_string(), "\"3\"".to_string())],
            "still there"
        );
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(session.objects().len(), 1, "only the refused one is held");
        assert_eq!(
            events[0],
            Event::Stored(Taken::new(
                "aws-s3://orders/in/1.edi",
                b"UNA:+.? '".to_vec()
            ))
        );
        let named = |key: &str| format!("aws-s3://orders/in/{key}");
        assert_matches!(events[3], Event::Listed { .. });
        assert_matches!(
            &events[4],
            Event::Stored(claim) if claim.origin_uri == named("1.edi.xmip-claim"),
            "claimed beside it"
        );
        assert_eq!(
            events[7..12],
            [
                Event::Retrieved(named("1.edi")),
                Event::Deleted(named("1.edi")),
                Event::Deleted(named("1.edi.xmip-claim")),
                Event::Deleted(named("2.edi.xmip-claim")),
                Event::Deleted(named("3.edi.xmip-claim"))
            ],
            "only what was read was got, only what was accepted deleted, every claim let go"
        );
        assert_matches!(events[12], Event::Listed { .. });
        assert_eq!(
            events[14..17],
            [
                Event::Retrieved(named("2.edi")),
                Event::Deleted(named("2.edi")),
                Event::Deleted(named("2.edi.xmip-claim"))
            ]
        );
        assert_matches!(events[17], Event::Listed { .. });
    }

    /// The start `start` of the node at `place`.
    fn located(place: &str, start: u128) -> NodeStart {
        let location = format!("process-{}/place-{place}", std::process::id());
        NodeStart::new(transport::NodeLocation::new(location), start)
    }

    /// Two Locations listing one bucket, built on `first` and on `second`:
    /// the first's claim is written, the second, starting, reads it, leaves
    /// it and receives nothing, and once the first accepts, the object and
    /// its claim are gone.
    fn one_receives_of(first: &NodeStart, second: &NodeStart) {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let on = |built_on: &NodeStart| {
            node(&format!("http://{address}"), "secret")
                .on_node(built_on)
                .expect("on its node")
        };
        let (first, second) = (on(first), on(second));
        // A put; the first's list and claim; the second's list, and its
        // read of the claim it finds as it starts; the first's get, delete
        // and its claim's; the second's list.
        let far_end = serve(first.session(), listener, 9);
        first.send("in/1.edi", b"once").expect("put");
        let won = first.receive().expect("listed");
        assert!(second.receive().expect("listed").is_empty(), "held");
        let taken = won.into_iter().next().expect("won").taken().expect("ok");
        assert_eq!(taken.bytes, b"once");
        assert!(second.receive().expect("listed").is_empty(), "gone");
        let (session, events) = far_end.join().expect("thread");
        assert!(session.objects().is_empty(), "the object and its claim");
        let claim = "aws-s3://orders/in/1.edi.xmip-claim".to_string();
        assert_eq!(events[4], Event::Retrieved(claim), "the first's, and left");
    }

    #[test]
    fn two_nodes_listing_one_bucket_never_both_receive_one_object() {
        one_receives_of(&located("first", 1), &located("second", 1));
    }

    #[test]
    fn two_locations_of_one_start_listing_one_bucket_never_both_receive_one_object() {
        let start = located("first", 1);
        one_receives_of(&start, &start);
    }

    #[test]
    fn a_refused_object_is_not_received_again_until_it_is_written_again() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), "secret");
        // A put; a list, a claim, its delete; a list; a put again; a list,
        // a claim, a get, a delete, its claim's.
        let far_end = serve(near.session(), listener, 11);
        near.send("in/1.edi", b"first").expect("put");
        let refused = near.receive().expect("received").remove(0);
        refused
            .refused(transport::Refusal::Forbidden)
            .expect("left");
        assert!(near.receive().expect("listed").is_empty(), "unchanged");
        near.send("in/1.edi", b"second").expect("written again");
        let again = near
            .receive()
            .expect("listed")
            .remove(0)
            .taken()
            .expect("ok");
        assert_eq!(again.bytes, b"second", "another ETag, a new arrival");
        let (session, _) = far_end.join().expect("thread");
        assert!(session.objects().is_empty(), "accepted, so deleted");
    }

    /// The bytes an arrival's body reads, and its acknowledgement, which
    /// the runtime gives only after the cycle.
    fn read(arrived: Arrived) -> (std::io::Result<Vec<u8>>, transport::Acknowledgement) {
        let (_, mut body, told) = arrived.into_parts();
        let mut bytes = Vec::new();
        let read = std::io::Read::read_to_end(&mut body, &mut bytes).map(|_| bytes);
        (read, told)
    }

    #[test]
    fn a_replacement_between_read_and_acceptance_stays_for_the_next_listing() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), "secret");
        // A put; a list, a claim, the get; the put replacing it; the delete
        // of the one read, which S3 refuses, and its claim's; a list, a
        // claim, a get, a delete and its claim's of the replacement.
        let far_end = serve(near.session(), listener, 12);
        near.send("in/1.edi", b"first").expect("put");
        let listed = near.receive().expect("listed").remove(0);
        let (read, told) = read(listed);
        assert_eq!(read.expect("read"), b"first");
        near.send("in/1.edi", b"second").expect("replaced");
        told.acknowledge(transport::Verdict::Accepted)
            .expect("the one read is done with: the replacement is not it");
        let again = near.receive().expect("listed again");
        assert_eq!(again.len(), 1, "the replacement stayed in the bucket");
        let again = again.into_iter().next().expect("one").taken().expect("ok");
        assert_eq!(again.bytes, b"second");
        let (session, events) = far_end.join().expect("thread");
        assert!(session.objects().is_empty(), "the replacement, accepted");
        assert_eq!(
            events[5],
            Event::Refused("PreconditionFailed".to_string()),
            "the delete held to the ETag listed"
        );
    }

    #[test]
    fn a_replacement_between_listing_and_first_read_is_not_read_under_the_old_stamp() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), "secret");
        // A put; a list, a claim; the put replacing it; the get under the
        // old ETag, which S3 refuses, and its claim's delete; a list, a
        // claim, a get, a delete and its claim's of the replacement.
        let far_end = serve(near.session(), listener, 11);
        near.send("in/1.edi", b"first").expect("put");
        let listed = near.receive().expect("listed").remove(0);
        near.send("in/1.edi", b"second").expect("replaced");
        let unread = listed.taken().expect_err("not read under the old ETag");
        assert!(
            unread.message.contains("changed since it was listed"),
            "{unread}"
        );
        let again = near.receive().expect("listed again");
        assert_eq!(again.len(), 1, "the failed read deleted nothing");
        let again = again.into_iter().next().expect("one").taken().expect("ok");
        assert_eq!(again.bytes, b"second", "read under its own ETag");
        let (session, events) = far_end.join().expect("thread");
        assert!(session.objects().is_empty(), "the replacement, accepted");
        assert_eq!(events[4], Event::Refused("PreconditionFailed".to_string()));
    }

    #[test]
    fn a_wrong_secret_is_refused_with_s3s_own_status_and_code() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = serve(node("http://x", "secret").session(), listener, 1);
        let failure = node(&format!("http://{address}"), "wrong")
            .send("in/1.edi", b"x")
            .expect_err("refused");
        assert!(
            failure.message.contains("403 SignatureDoesNotMatch"),
            "{failure}"
        );
        assert!(!failure.retryable);
        let (_, events) = far_end.join().expect("thread");
        assert_eq!(
            events,
            vec![Event::Refused("SignatureDoesNotMatch".to_string())]
        );
    }

    #[test]
    fn objects_are_claimed_artifacts_and_an_unreachable_endpoint_is_retryable() {
        let near = node("http://127.0.0.1:1", "secret");
        assert!(near.claims().is_some());
        assert_eq!(near.name(), "aws-s3");
        assert!(near.directions().receives() && near.directions().sends());
        assert!(near.receive().expect_err("nothing listening").retryable);
        let failure = node("orders.local", "s")
            .send("k", b"")
            .expect_err("no scheme");
        assert!(!failure.retryable);
    }

    #[test]
    fn the_loopback_stores_one_object_through_its_own_session() {
        let pair = S3Transport::loopback();
        let arrived = pair.round(b"an object").expect("round");
        assert_eq!(arrived.bytes, b"an object");
        assert_eq!(arrived.origin_uri, "aws-s3://probe/probe.bin");
        assert_eq!(pair.name(), "aws-s3");
        assert_eq!(pair.ceiling(), None);
    }

    /// The System Tests' edge payloads, written here so the crate does not
    /// depend on them.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = S3Transport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    /// A Location signs as its `access_key_id` with the secret access key
    /// the secret it names holds, read at each request (ADR-0015, amendment
    /// 2026-11-25).
    #[test]
    fn a_location_signs_with_the_secret_it_names_as_its_access_key_id() {
        use std::sync::Arc;
        use transport::secured::Kept;
        use xcore::settings::Given;
        let drawn = Kept::drawn();
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{address}");
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("region", "eu-north-1"),
            text("bucket", "orders"),
            text("access_key_id", "AKIDPROBE"),
        ];
        let kept = Arc::new(Kept::default());
        let near = S3Transport::open(&endpoint, Applies::Send, &given)
            .expect("built")
            .timing_out_after(Duration::from_secs(2))
            .secured_by(kept.secured("partner-x.s3"))
            .expect("presents its secret");
        let unset = near.send("in/1.edi", b"UNA").expect_err("not set");
        assert!(
            unset.retryable && unset.message.contains("is not set"),
            "{unset}"
        );

        kept.set("partner-x.s3", xcore::SecretKind::Password, &drawn);
        let far = Session::new("eu-north-1", "AKIDPROBE", &drawn);
        let far_end = serve(far.timing_out_after(Duration::from_secs(2)), listener, 1);
        near.send("in/1.edi", b"UNA")
            .expect("signed with the secret");
        let (_, events) = far_end.join().expect("thread");
        assert_eq!(
            events,
            [Event::Stored(Taken::new(
                "aws-s3://orders/in/1.edi",
                b"UNA".to_vec()
            ))]
        );

        let unnamed = S3Transport::open(&endpoint, Applies::Send, &given[..2]).expect("built");
        let Err(refused) = unnamed.secured_by(kept.secured("partner-x.s3")) else {
            panic!("no access key ID to sign as");
        };
        assert!(!refused.retryable);
        assert!(refused.message.contains("\"access_key_id\""), "{refused}");
    }
}
