//! The network side of signing, kept out of the sign crate (which never fetches): an RFC 3161
//! time-stamp authority reached over HTTP, and fetching the OCSP responses and CRLs that make a
//! signature verifiable long after its certificates expire (PAdES B-LT).

use std::time::Duration;

use pdfcraft_engine::sign::revocation::{CertId, CertificateList, OcspResponse, RevocationStatus, encode_ocsp_request};
use pdfcraft_engine::sign::{self, Certificate, DigestAlg, SignError, Time};
use serde_json::{Value, json};

/// The largest reply read: real time-stamp tokens, OCSP responses and CRLs are far smaller.
const LIMIT: u64 = 8 * 1024 * 1024;

/// Seconds a call may take before it gives up, unless the caller says otherwise.
pub(crate) const DEFAULT_TIMEOUT: u64 = 30;

fn agent(timeout: u64) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(timeout.clamp(1, 600)))).build().into()
}

/// Only web addresses are fetched: no files, no LDAP.
pub(crate) fn check_url(url: &str) -> Result<(), String> {
    let l = url.trim().to_ascii_lowercase();
    if (l.starts_with("http://") || l.starts_with("https://")) && l.len() > "https://".len() {
        Ok(())
    } else {
        Err(format!("{url:?} is not an http:// or https:// address"))
    }
}

fn post(url: &str, content_type: &str, body: &[u8], timeout: u64) -> Result<Vec<u8>, String> {
    check_url(url)?;
    let mut reply = agent(timeout).post(url.trim()).header("Content-Type", content_type).send(body).map_err(|e| e.to_string())?;
    reply.body_mut().with_config().limit(LIMIT).read_to_vec().map_err(|e| e.to_string())
}

fn get(url: &str, timeout: u64) -> Result<Vec<u8>, String> {
    check_url(url)?;
    let mut reply = agent(timeout).get(url.trim()).call().map_err(|e| e.to_string())?;
    reply.body_mut().with_config().limit(LIMIT).read_to_vec().map_err(|e| e.to_string())
}

/// A time-stamp authority at an HTTP address (RFC 3161 §3.4: the request is POSTed as
/// `application/timestamp-query`). The engine builds the request and checks the token.
pub(crate) struct HttpTsa {
    pub url: String,
    pub timeout: u64,
}

impl sign::TimestampAuthority for HttpTsa {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        post(&self.url, "application/timestamp-query", request, self.timeout)
            .map_err(|e| SignError::Unsupported(format!("the time-stamp authority {} did not answer: {e}", self.url)))
    }
}

/// What was fetched for long-term validation, and a line per certificate saying how.
#[derive(Default)]
pub(crate) struct Fetched {
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub log: Vec<Value>,
}

fn self_signed(c: &Certificate) -> bool {
    c.subject.raw == c.issuer.raw
}

fn status(s: RevocationStatus) -> &'static str {
    match s {
        RevocationStatus::Good => "good",
        RevocationStatus::Revoked { .. } => "revoked",
        RevocationStatus::Unknown => "unknown",
    }
}

/// For every certificate in `certs` that isn't a root, its revocation evidence: an OCSP response
/// from its responder, else a CRL from its distribution point. Issuers are looked up in `certs`.
/// Nothing fails the call: what couldn't be fetched is in the log.
pub(crate) fn fetch_revocation(certs: &[Certificate], at: Time, timeout: u64) -> Fetched {
    let mut out = Fetched::default();
    let mut crl_seen = std::collections::HashSet::new();
    for cert in certs {
        if self_signed(cert) {
            continue;
        }
        let name = cert.display_name();
        let Some(issuer) = certs.iter().find(|c| c.subject.raw == cert.issuer.raw && c.raw != cert.raw) else {
            out.log.push(json!({ "certificate": name, "ok": false, "error": "its issuer's certificate is not in the chain; pass it in certs" }));
            continue;
        };
        let mut done = false;
        let mut errors = Vec::new();
        for url in &cert.ocsp_urls {
            let request = encode_ocsp_request(&[CertId::build(cert, issuer, DigestAlg::Sha1)]);
            match post(url, "application/ocsp-request", &request, timeout).and_then(|b| OcspResponse::parse(&b).map(|r| (b, r)).map_err(|e| e.to_string())) {
                Ok((bytes, response)) => {
                    let s = status(response.check(cert, issuer, at));
                    out.log.push(json!({ "certificate": name, "ok": true, "source": "ocsp", "url": url, "status": s }));
                    out.ocsps.push(bytes);
                    done = true;
                    break;
                }
                Err(e) => errors.push(format!("OCSP {url}: {e}")),
            }
        }
        if !done {
            for url in cert.crl_urls.iter().filter(|u| check_url(u).is_ok()) {
                if crl_seen.contains(url) {
                    out.log.push(json!({ "certificate": name, "ok": true, "source": "crl", "url": url, "status": "already fetched" }));
                    done = true;
                    break;
                }
                match get(url, timeout).and_then(|b| CertificateList::parse(&b).map(|l| (b, l)).map_err(|e| e.to_string())) {
                    Ok((bytes, list)) => {
                        let s = status(list.check(cert, issuer, at));
                        out.log.push(json!({ "certificate": name, "ok": true, "source": "crl", "url": url, "status": s }));
                        out.crls.push(bytes);
                        crl_seen.insert(url.clone());
                        done = true;
                        break;
                    }
                    Err(e) => errors.push(format!("CRL {url}: {e}")),
                }
            }
        }
        if !done {
            let error = if errors.is_empty() { "its certificate names no OCSP responder or http CRL".to_string() } else { errors.join("; ") };
            out.log.push(json!({ "certificate": name, "ok": false, "error": error }));
        }
    }
    out
}
