//! HTTP fetch for malware intelligence feeds.

use std::io::Read;
use std::time::Duration;

use serde_json::Value;

use crate::model::Ecosystem;

use super::{
    AvailableFeed, EcosystemIntelligence, FeedFailure, FetchLimits, IntelligenceProvenance,
    parse::parse_malware_feed_value,
};

pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn map_ureq_error(err: ureq::Error) -> FeedFailure {
    match err {
        ureq::Error::Timeout(_) => FeedFailure::Timeout,
        ureq::Error::BodyExceedsLimit(_) => FeedFailure::OversizedResponse,
        _ => FeedFailure::Network,
    }
}

fn map_read_error(err: std::io::Error) -> FeedFailure {
    map_ureq_error(ureq::Error::from(err))
}

pub(crate) fn http_agent(limits: FetchLimits) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(limits.timeout))
        .user_agent(format!("chaincheck/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

fn header_u64(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<u64> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse().ok())
}

fn header_string(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

pub(crate) fn read_response_body(
    response: &mut ureq::http::Response<ureq::Body>,
    limits: FetchLimits,
) -> Result<Vec<u8>, FeedFailure> {
    if let Some(declared) = header_u64(response, "content-length") {
        if declared > limits.max_body_bytes {
            return Err(FeedFailure::OversizedResponse);
        }
    }

    let max_plus_one = limits.max_body_bytes.saturating_add(1);
    let mut reader = response
        .body_mut()
        .with_config()
        .limit(max_plus_one)
        .reader();
    let mut buf = Vec::new();
    reader
        .by_ref()
        .take(max_plus_one)
        .read_to_end(&mut buf)
        .map_err(map_read_error)?;
    if buf.len() as u64 > limits.max_body_bytes {
        return Err(FeedFailure::OversizedResponse);
    }
    Ok(buf)
}

pub(crate) fn parse_response_with_records(
    bytes: &[u8],
    ecosystem: Ecosystem,
    etag: Option<String>,
    provenance: IntelligenceProvenance,
) -> Result<(AvailableFeed, Value), FeedFailure> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FeedFailure::InvalidJson)?;
    let feed = parse_malware_feed_value(&value, ecosystem)?
        .with_etag(etag)
        .with_provenance(provenance);
    Ok((feed, value))
}

pub(crate) fn fetch_unconditional_with_records(
    url: &str,
    ecosystem: Ecosystem,
    limits: FetchLimits,
) -> Result<(AvailableFeed, Value), FeedFailure> {
    let agent = http_agent(limits);
    let mut response = agent.get(url).call().map_err(map_ureq_error)?;
    if !response.status().is_success() {
        return Err(FeedFailure::Network);
    }
    let etag = header_string(&response, "etag");
    let body = read_response_body(&mut response, limits)?;
    parse_response_with_records(&body, ecosystem, etag, IntelligenceProvenance::Live)
}

pub(crate) fn fetch_unconditional(
    url: &str,
    ecosystem: Ecosystem,
    limits: FetchLimits,
) -> Result<AvailableFeed, FeedFailure> {
    fetch_unconditional_with_records(url, ecosystem, limits).map(|(feed, _)| feed)
}

pub fn fetch_feed_url(
    url: &str,
    ecosystem: Ecosystem,
    limits: FetchLimits,
) -> EcosystemIntelligence {
    match fetch_unconditional(url, ecosystem, limits) {
        Ok(feed) => EcosystemIntelligence::Available(feed),
        Err(failure) => EcosystemIntelligence::Unavailable(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::MalwareMatch;
    use crate::model::{PackageIdentity, PackageVersion};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    const VALID_NPM: &str = include_str!("../../tests/fixtures/feeds/valid-npm.json");
    const VALID_GZIP: &[u8] = include_bytes!("../../tests/fixtures/feeds/valid-gzip.bin");
    const BOMB_GZIP: &[u8] = include_bytes!("../../tests/fixtures/feeds/bomb-gzip.bin");

    fn tiny_limits(max_body_bytes: u64, timeout_ms: u64) -> FetchLimits {
        FetchLimits {
            max_body_bytes,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    struct Served {
        url: String,
        handle: thread::JoinHandle<()>,
        captured_request: Arc<Mutex<Vec<u8>>>,
    }

    fn serve_http(
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
        chunked: bool,
        stall: bool,
    ) -> Served {
        let captured_request = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&captured_request);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let body = body.to_vec();
        let handle = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut tmp = [0u8; 1024];
            let mut req = Vec::new();
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&tmp[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if let Ok(mut guard) = captured.lock() {
                *guard = req;
            }
            if stall {
                thread::sleep(Duration::from_millis(800));
                return;
            }
            let reason = match status {
                200 => "OK",
                304 => "Not Modified",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Error",
            };
            let mut head = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
            if chunked {
                head.push_str("Transfer-Encoding: chunked\r\n");
                for (k, v) in &headers {
                    if !k.eq_ignore_ascii_case("content-length") {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = write!(stream, "{:x}\r\n", body.len());
                let _ = stream.write_all(&body);
                let _ = stream.write_all(b"\r\n0\r\n\r\n");
            } else {
                let mut has_len = false;
                for (k, v) in &headers {
                    if k.eq_ignore_ascii_case("content-length") {
                        has_len = true;
                    }
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                if !has_len && status != 304 {
                    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                if status != 304 {
                    let _ = stream.write_all(&body);
                }
            }
            let _ = stream.flush();
        });
        Served {
            url: format!("http://{addr}/feed"),
            handle,
            captured_request,
        }
    }

    fn join(served: Served) {
        let _ = served.handle.join();
    }

    fn request_text(served: &Served) -> String {
        let bytes = served.captured_request.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn fetch_success_captures_etag() {
        let served = serve_http(
            200,
            &[("ETag", "\"abc123\"")],
            VALID_NPM.as_bytes(),
            false,
            false,
        );
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(4096, 2_000));
        join(served);
        match intel {
            EcosystemIntelligence::Available(feed) => {
                assert_eq!(feed.etag(), Some("\"abc123\""));
                assert_eq!(feed.accepted_records(), 4);
            }
            other => panic!("expected available, got {other:?}"),
        }
    }

    #[test]
    fn http_status_failures_are_network() {
        let served = serve_http(404, &[], b"missing", false, false);
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(4096, 2_000));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        );

        let served = serve_http(500, &[], b"err", false, false);
        let intel = fetch_feed_url(&served.url, Ecosystem::Pypi, tiny_limits(4096, 2_000));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        );
    }

    #[test]
    fn connect_failure_is_network() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{addr}/feed");
        let intel = fetch_feed_url(&url, Ecosystem::Npm, tiny_limits(4096, 2_000));
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        );
    }

    #[test]
    fn stall_is_timeout() {
        let served = serve_http(200, &[], VALID_NPM.as_bytes(), false, true);
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(4096, 150));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::Timeout)
        );
    }

    #[test]
    fn content_length_oversize_is_rejected() {
        let served = serve_http(
            200,
            &[("Content-Length", "100")],
            VALID_NPM.as_bytes(),
            false,
            false,
        );
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(16, 2_000));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::OversizedResponse)
        );
    }

    #[test]
    fn body_oversize_without_content_length() {
        let body = vec![b'x'; 32];
        let served = serve_http(200, &[], &body, false, false);
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(16, 2_000));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::OversizedResponse)
        );
    }

    #[test]
    fn chunked_oversize_is_rejected() {
        let body = vec![b'y'; 32];
        let served = serve_http(200, &[], &body, true, false);
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(16, 2_000));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::OversizedResponse)
        );
    }

    #[test]
    fn gzip_decoded_body_under_cap_succeeds() {
        let served = serve_http(
            200,
            &[("Content-Encoding", "gzip")],
            VALID_GZIP,
            false,
            false,
        );
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(4096, 2_000));
        join(served);
        match intel {
            EcosystemIntelligence::Available(feed) => {
                assert_eq!(
                    feed.index().matches(
                        &PackageIdentity::npm("gz-pkg"),
                        Some(&PackageVersion::exact("1.0.0")),
                    ),
                    Some(MalwareMatch::Exact)
                );
            }
            other => panic!("expected available gzip feed, got {other:?}"),
        }
    }

    #[test]
    fn gzip_that_expands_past_cap_is_oversized() {
        const CAP: u64 = 100;
        const DECODED_BOMB_BYTES: u64 = 1198;
        assert!(
            (BOMB_GZIP.len() as u64) < CAP,
            "compressed fixture ({} bytes) must be smaller than the cap",
            BOMB_GZIP.len()
        );
        assert!(
            DECODED_BOMB_BYTES > CAP,
            "decoded fixture must exceed the cap so expansion is what trips the limit"
        );
        let served = serve_http(
            200,
            &[("Content-Encoding", "gzip")],
            BOMB_GZIP,
            false,
            false,
        );
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(CAP, 2_000));
        join(served);
        assert_eq!(
            intel,
            EcosystemIntelligence::Unavailable(FeedFailure::OversizedResponse)
        );
    }

    #[test]
    fn small_content_length_does_not_allow_unbounded_body() {
        let huge = vec![b'z'; 256];
        let served = serve_http(200, &[("Content-Length", "4")], &huge, false, false);
        let intel = fetch_feed_url(&served.url, Ecosystem::Npm, tiny_limits(32, 2_000));
        join(served);
        assert!(matches!(
            intel,
            EcosystemIntelligence::Unavailable(
                FeedFailure::OversizedResponse
                    | FeedFailure::InvalidJson
                    | FeedFailure::Network
                    | FeedFailure::NoValidMalwareRecords
            )
        ));
        assert!(!matches!(intel, EcosystemIntelligence::Available(_)));
    }

    #[test]
    fn unconditional_get_omits_if_none_match() {
        let served = serve_http(200, &[], VALID_NPM.as_bytes(), false, false);
        let _ = fetch_unconditional(&served.url, Ecosystem::Npm, tiny_limits(4096, 2_000));
        let req = request_text(&served);
        join(served);
        assert!(!req.to_ascii_lowercase().contains("if-none-match"));
    }
}
