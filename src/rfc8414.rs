//! # OAuth 2.0 Authorization Server Metadata (RFC 8414)
//!
//! [`DiscoveryOauthServerResolve`] GETs an authorization server's well-known
//! metadata document and parses it into [`DiscoveryOauthServerMetadata`]
//! (authorization/token/registration endpoints, supported grants and
//! scopes). It resolves an issuer surfaced elsewhere (a PACC
//! `oauth-public` issuer, say) into the concrete endpoints a client
//! needs, so discovery can hand back usable grants instead of a bare
//! issuer URL.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc8414>

use alloc::{string::String, vec::Vec};

use io_http::{
    coroutine::{HttpCoroutine, HttpCoroutineState},
    rfc9110::{
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield};

/// The metadata describing an authorization server's configuration.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8414#section-2>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryOauthServerMetadata {
    /// The authorization server's issuer identifier.
    pub issuer: Url,

    /// URL of the authorization endpoint (RFC 6749 §3.1).
    pub authorization_endpoint: Option<Url>,

    /// URL of the token endpoint (RFC 6749 §3.2).
    pub token_endpoint: Option<Url>,

    /// URL of the JWK Set document (RFC 7517).
    pub jwks_uri: Option<Url>,

    /// URL of the dynamic client registration endpoint (RFC 7591).
    pub registration_endpoint: Option<Url>,

    /// The scope values this server supports.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// The `response_type` values this server supports.
    #[serde(default)]
    pub response_types_supported: Vec<String>,

    /// The `response_mode` values this server supports.
    #[serde(default)]
    pub response_modes_supported: Vec<String>,

    /// The grant types this server supports.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,

    /// The client authentication methods the token endpoint supports
    /// (`none` means public clients need no secret).
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// URL of the developer documentation.
    pub service_documentation: Option<Url>,

    /// URL of the token revocation endpoint (RFC 7009).
    pub revocation_endpoint: Option<Url>,

    /// URL of the token introspection endpoint (RFC 7662).
    pub introspection_endpoint: Option<Url>,

    /// The PKCE code challenge methods this server supports
    /// (RFC 7636).
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,

    /// URL of the device authorization endpoint (RFC 8628 §4).
    pub device_authorization_endpoint: Option<Url>,
}

impl DiscoveryOauthServerMetadata {
    /// Builds the metadata's well-known URL for an issuer, inserting
    /// the well-known path between host and issuer path components.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8414#section-3.1>
    pub fn well_known_url(issuer: &Url) -> Url {
        insert_well_known(issuer, "/.well-known/oauth-authorization-server")
    }

    /// Builds the OpenID Connect Discovery compatibility URL for an
    /// issuer, appending the well-known path after the issuer path.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8414#section-5>
    pub fn openid_well_known_url(issuer: &Url) -> Url {
        let mut url = issuer.clone();
        let path = issuer.path().trim_end_matches('/');
        url.set_path(&format!("{path}/.well-known/openid-configuration"));
        url.set_query(None);
        url.set_fragment(None);
        url
    }
}

/// Deserializes server metadata from JSON bytes.
impl TryFrom<&[u8]> for DiscoveryOauthServerMetadata {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Inserts a well-known path between the host and path components of
/// a URL, per the RFC 8414 §3.1 transformation (shared with RFC 9728
/// §3.1, which uses the same rule for resources).
pub(crate) fn insert_well_known(url: &Url, well_known: &str) -> Url {
    let mut transformed = url.clone();
    let path = url.path().trim_end_matches('/');
    transformed.set_path(&format!("{well_known}{path}"));
    transformed.set_query(None);
    transformed.set_fragment(None);
    transformed
}

/// Errors emitted by [`DiscoveryOauthServerResolve`].
#[derive(Debug, Error)]
pub enum DiscoveryOauthServerResolveError {
    /// Sending the HTTP metadata request failed.
    #[error(transparent)]
    SendHttpFetch(#[from] Http11SendError),
    /// The metadata JSON response could not be parsed.
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    /// The metadata endpoint answered with an unexpected redirect.
    #[error("Unexpected redirection {code} to {url}")]
    Redirect {
        /// Location the server redirected to.
        url: Url,
        /// HTTP status code of the redirect response.
        code: u16,
    },
    /// The metadata endpoint answered with an unexpected status.
    #[error("Unexpected status {code} fetching server metadata")]
    Status {
        /// HTTP status code returned.
        code: u16,
    },
}

/// I/O-free coroutine that GETs an authorization server's well-known
/// metadata URL (built with [`DiscoveryOauthServerMetadata::well_known_url`],
/// falling back to [`DiscoveryOauthServerMetadata::openid_well_known_url`] on a
/// rebuilt coroutine when the server only publishes the OpenID Connect
/// Discovery document) and parses the JSON metadata. Yields its target
/// URL on every step so the std client routes bytes through the
/// matching HTTPS stream.
pub struct DiscoveryOauthServerResolve {
    target: Url,
    send: Http11Send,
}

impl DiscoveryOauthServerResolve {
    /// Builds a coroutine fetching the metadata document at `url`.
    pub fn new(url: Url) -> Self {
        let request = HttpRequest::get(url.clone()).header("Accept", "application/json");

        Self {
            target: url,
            send: Http11Send::new(request),
        }
    }
}

impl DiscoveryCoroutine for DiscoveryOauthServerResolve {
    type Yield = DiscoveryYield;
    type Return = Result<DiscoveryOauthServerMetadata, DiscoveryOauthServerResolveError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryCoroutineState<Self::Yield, Self::Return> {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match DiscoveryOauthServerMetadata::try_from(response.body.as_slice()) {
                    Ok(metadata) => DiscoveryCoroutineState::Complete(Ok(metadata)),
                    Err(err) => DiscoveryCoroutineState::Complete(Err(err.into())),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                DiscoveryCoroutineState::Complete(Err(DiscoveryOauthServerResolveError::Status {
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
                DiscoveryCoroutineState::Complete(Err(DiscoveryOauthServerResolveError::Redirect {
                    url,
                    code: *response.status,
                }))
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

    use crate::rfc8414::DiscoveryOauthServerMetadata;

    #[test]
    fn well_known_urls_follow_the_transformation_rules() {
        let bare: Url = "https://example.com".parse().unwrap();
        assert_eq!(
            DiscoveryOauthServerMetadata::well_known_url(&bare).as_str(),
            "https://example.com/.well-known/oauth-authorization-server",
        );
        assert_eq!(
            DiscoveryOauthServerMetadata::openid_well_known_url(&bare).as_str(),
            "https://example.com/.well-known/openid-configuration",
        );

        // RFC 8414 §3.1: path components insert AFTER the well-known
        // segment; the OpenID compatibility form appends instead.
        let issuer: Url = "https://example.com/issuer1".parse().unwrap();
        assert_eq!(
            DiscoveryOauthServerMetadata::well_known_url(&issuer).as_str(),
            "https://example.com/.well-known/oauth-authorization-server/issuer1",
        );
        assert_eq!(
            DiscoveryOauthServerMetadata::openid_well_known_url(&issuer).as_str(),
            "https://example.com/issuer1/.well-known/openid-configuration",
        );
    }

    #[test]
    fn metadata_parses_a_minimal_document() {
        let json = br#"{
            "issuer": "https://api.example.com",
            "registration_endpoint": "https://api.example.com/oauth/register",
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"]
        }"#;

        let metadata = DiscoveryOauthServerMetadata::try_from(json.as_slice()).unwrap();
        assert_eq!(metadata.issuer.as_str(), "https://api.example.com/");
        assert!(metadata.registration_endpoint.is_some());
        assert_eq!(metadata.token_endpoint_auth_methods_supported, ["none"]);
        assert!(metadata.scopes_supported.is_empty());
    }
}
