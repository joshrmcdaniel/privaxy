pub(crate) mod doh;
pub(crate) mod mitm;
pub(crate) mod serve;
pub(crate) use mitm::serve_mitm_session;
pub(crate) mod exclusions;
pub(crate) mod html_rewriter;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use tokio_stream::wrappers::ReceiverStream;

/// Response body type used throughout the proxy. hyper 1.0 removed the built-in
/// `hyper::Body`, so we standardize on a boxed body of `Bytes` with an
/// `io::Error` error type (the channel/stream bodies below can surface IO
/// errors; the static bodies never do).
pub(crate) type ProxyBody = BoxBody<Bytes, std::io::Error>;

/// Sending half of a streaming response body. Replaces `hyper::body::Sender`
/// (removed in hyper 1.0). Sending `Err` when the receiver has been dropped
/// signals the producer to stop, matching the old `Sender::send_data`
/// back-pressure/abort semantics. The bounded capacity preserves the
/// back-pressure the old channel body provided.
pub(crate) type BodySender = tokio::sync::mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>;

/// hyper 1.0 replacement for `hyper::Body::channel()`: returns a sender plus a
/// streaming body fed by it.
pub(crate) fn body_channel() -> (BodySender, ProxyBody) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(32);
    let body = StreamBody::new(ReceiverStream::new(rx)).boxed();
    (tx, body)
}

/// An empty response body (replaces `hyper::Body::empty()`).
pub(crate) fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// A fully-buffered response body (replaces `hyper::Body::from(..)`).
pub(crate) fn full_body<B: Into<Bytes>>(chunk: B) -> ProxyBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Box an upstream `hyper::body::Incoming` into our `ProxyBody`, mapping
/// hyper's body error onto `io::Error` (used when forwarding an upstream
/// response through unchanged).
pub(crate) fn boxed_incoming(incoming: hyper::body::Incoming) -> ProxyBody {
    incoming.map_err(std::io::Error::other).boxed()
}
