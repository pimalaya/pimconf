//! # OAuth 2.0 Protected Resource Metadata (RFC 9728)
//!
//! [`DiscoveryOauthResourceResolve`] GETs a protected resource's well-known
//! metadata document (or the URL a 401 pointed at, see
//! [`challenge_resource_metadata`]) and parses it into
//! [`DiscoveryOauthResourceMetadata`], whose `authorization_servers` point at
//! the RFC 8414 metadata that can issue tokens for the resource. It is
//! the structured follow-up to the `WWW-Authenticate` scheme probe.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc9728>

use alloc::{string::String, vec::Vec};

use io_http::{
    coroutine::{HttpCoroutine, HttpCoroutineState},
    rfc9110::{
        challenge::HttpChallenge,
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc8414::insert_well_known,
};

/// The metadata describing a protected resource's configuration,
/// pointing clients at the authorization servers that can issue
/// tokens for it.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc9728#section-2>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryOauthResourceMetadata {
    /// The resource's identifier.
    pub resource: Url,

    /// Issuer identifiers of the authorization servers that can be
    /// used with this resource; each resolves to its RFC 8414
    /// metadata.
    #[serde(default)]
    pub authorization_servers: Vec<Url>,

    /// URL of the resource's JWK Set document (RFC 7517).
    pub jwks_uri: Option<Url>,

    /// The scope values used in authorization requests to access this
    /// resource.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// The bearer token presentation methods this resource supports
    /// (`header`, `body`, `query`; RFC 6750).
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,

    /// Human-readable name of the resource.
    pub resource_name: Option<String>,

    /// URL of the resource's developer documentation.
    pub resource_documentation: Option<Url>,

    /// URL of the resource's usage policy.
    pub resource_policy_uri: Option<Url>,

    /// URL of the resource's terms of service.
    pub resource_tos_uri: Option<Url>,
}

impl DiscoveryOauthResourceMetadata {
    /// Builds the metadata's well-known URL for a resource, inserting
    /// the well-known path between host and resource path components
    /// (the same transformation rule as RFC 8414 §3.1).
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc9728#section-3.1>
    pub fn well_known_url(resource: &Url) -> Url {
        insert_well_known(resource, "/.well-known/oauth-protected-resource")
    }
}

/// Deserializes resource metadata from JSON bytes.
impl TryFrom<&[u8]> for DiscoveryOauthResourceMetadata {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Extracts the `resource_metadata` parameter of a `WWW-Authenticate`
/// header value (parsed by io-http's rfc9110 challenge module): the
/// URL a protected resource points its 401s at, so a client discovers
/// the metadata without knowing the well-known rule.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc9728#section-5.1>
pub fn challenge_resource_metadata(value: &str) -> Option<Url> {
    HttpChallenge::parse_all(value)
        .iter()
        .find_map(|challenge| challenge.param("resource_metadata"))
        .and_then(|url| Url::parse(url).ok())
}

/// Errors emitted by [`DiscoveryOauthResourceResolve`].
#[derive(Debug, Error)]
pub enum DiscoveryOauthResourceResolveError {
    #[error(transparent)]
    SendHttpFetch(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
    #[error("Unexpected status {code} fetching resource metadata")]
    Status { code: u16 },
}

/// I/O-free coroutine that GETs a protected resource's metadata URL
/// (from a `WWW-Authenticate` challenge via
/// [`challenge_resource_metadata`], or built with
/// [`DiscoveryOauthResourceMetadata::well_known_url`]) and parses the JSON
/// metadata. Yields its target URL on every step so the std client
/// routes bytes through the matching HTTPS stream.
pub struct DiscoveryOauthResourceResolve {
    target: Url,
    send: Http11Send,
}

impl DiscoveryOauthResourceResolve {
    /// Builds a coroutine fetching the metadata document at `url`.
    pub fn new(url: Url) -> Self {
        let request = HttpRequest::get(url.clone()).header("Accept", "application/json");

        Self {
            target: url,
            send: Http11Send::new(request),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryOauthResourceResolve {
    type Yield = DiscoveryYield;
    type Return = Result<DiscoveryOauthResourceMetadata, DiscoveryOauthResourceResolveError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match DiscoveryOauthResourceMetadata::try_from(response.body.as_slice()) {
                    Ok(metadata) => DiscoveryCoroutineState::Complete(Ok(metadata)),
                    Err(err) => DiscoveryCoroutineState::Complete(Err(err.into())),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                DiscoveryCoroutineState::Complete(Err(DiscoveryOauthResourceResolveError::Status {
                    code: *response.status,
                }))
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead {
                    url: self.target.clone(),
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite {
                    url: self.target.clone(),
                    bytes,
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                DiscoveryCoroutineState::Complete(Err(
                    DiscoveryOauthResourceResolveError::Redirect {
                        url,
                        code: *response.status,
                    },
                ))
            }
            HttpCoroutineState::Complete(Err(err)) => {
                DiscoveryCoroutineState::Complete(Err(err.into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::rfc9728::{DiscoveryOauthResourceMetadata, challenge_resource_metadata};

    #[test]
    fn well_known_url_inserts_the_resource_path() {
        let resource: Url = "https://api.example.com/jmap/session".parse().unwrap();
        assert_eq!(
            DiscoveryOauthResourceMetadata::well_known_url(&resource).as_str(),
            "https://api.example.com/.well-known/oauth-protected-resource/jmap/session",
        );
    }

    #[test]
    fn challenge_yields_the_metadata_url() {
        // The fastmail shape: one Bearer challenge, quoted parameter.
        let challenge = r#"Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/jmap/session""#;
        let url = challenge_resource_metadata(challenge).unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.example.com/.well-known/oauth-protected-resource/jmap/session",
        );

        // Extra challenges and parameters ride along.
        let challenge = r#"Basic realm="dav", Bearer resource_metadata="https://example.com/meta", error="invalid_token""#;
        let url = challenge_resource_metadata(challenge).unwrap();
        assert_eq!(url.as_str(), "https://example.com/meta");

        assert!(challenge_resource_metadata("Bearer realm=\"x\"").is_none());
        assert!(challenge_resource_metadata("Bearer resource_metadata=").is_none());
    }
}
