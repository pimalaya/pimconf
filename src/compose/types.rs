//! # Unified compose types
//!
//! The compose module reduces every discovery mechanism to one common
//! output: a list of [`DiscoveryServiceConfig`], each describing one way to
//! reach one service (endpoint, login, authentication methods),
//! tagged with the mechanism that produced it. Conversion helpers on
//! [`DiscoveryServiceConfig`] flatten each mechanism's native document into
//! that shape.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};
use url::Url;

#[cfg(feature = "autoconfig")]
use crate::autoconfig::types::{AuthenticationType, Autoconfig, SecurityType, ServerType};
use crate::compose::providers::Provider;
#[cfg(feature = "pacc")]
use crate::pacc::types::PaccConfig;
#[cfg(feature = "rfc6186")]
use crate::rfc6186::types::{SrvReport, SrvService};

/// One discovered way to use one service: where to connect, how to
/// authenticate, and which mechanism found it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryServiceConfig {
    /// The service this config describes.
    pub service: DiscoveryService,

    /// Where to reach the service.
    pub endpoint: Endpoint,

    /// The login to present, when the mechanism advertises one
    /// (autoconfig placeholders already substituted).
    pub username: Option<String>,

    /// The authentication methods the service accepts.
    pub auth: Vec<DiscoveryAuthMethod>,

    /// The mechanism that produced this config.
    pub source: ConfigSource,
}

impl DiscoveryServiceConfig {
    /// The URLs whose unauthenticated 401 may advertise the config's
    /// schemes (to feed [`refine_auth`]): the HTTP endpoint itself,
    /// then the service's well-known path for the DAV services (some
    /// servers, fastmail among them, 404 the bare origin but guard
    /// the well-known walk). Empty for TCP endpoints.
    ///
    /// [`refine_auth`]: Self::refine_auth
    pub fn probe_urls(&self) -> Vec<Url> {
        let Endpoint::Http(raw) = &self.endpoint else {
            return Vec::new();
        };
        let Ok(url) = Url::parse(raw) else {
            return Vec::new();
        };

        let mut urls = vec![url.clone()];
        let well_known = match self.service {
            DiscoveryService::Caldav => Some("/.well-known/caldav"),
            DiscoveryService::Carddav => Some("/.well-known/carddav"),
            _ => None,
        };
        if let Some(path) = well_known {
            let mut probe = url;
            probe.set_path(path);
            urls.push(probe);
        }

        urls
    }

    /// Refines the password and bearer methods from the schemes the
    /// service endpoint advertised on its unauthenticated 401 (PACC
    /// §5.4.2): the endpoint's own advertisement beats any
    /// account-level claim, since a provider may take passwords on one
    /// service and only bearer tokens on another (fastmail does).
    /// OAuth methods stay untouched (they describe how to obtain a
    /// token, not a scheme), and schemes naming neither `basic` nor
    /// `bearer` leave the config as discovered.
    pub fn refine_auth(&mut self, schemes: &[String]) {
        let mut auth = Vec::new();

        for scheme in schemes {
            match scheme.as_str() {
                "basic" => auth.push(DiscoveryAuthMethod::Password),
                "bearer" => auth.push(DiscoveryAuthMethod::Bearer),
                _ => (),
            }
        }
        if auth.is_empty() {
            return;
        }

        for method in self.auth.drain(..) {
            let probed = matches!(
                method,
                DiscoveryAuthMethod::Password | DiscoveryAuthMethod::Bearer
            );
            if !probed && !auth.contains(&method) {
                auth.push(method);
            }
        }
        self.auth = auth;
    }

    /// Flattens a Mozilla autoconfig document into one config per
    /// incoming/outgoing server. Servers without a hostname are
    /// skipped; a missing port falls back to the well-known port of
    /// the service and security combination.
    #[cfg(feature = "autoconfig")]
    pub fn from_autoconfig(config: &Autoconfig, email: &str, source: ConfigSource) -> Vec<Self> {
        let provider = &config.email_provider;
        let servers = provider
            .incoming_server
            .iter()
            .chain(&provider.outgoing_server);

        let mut configs = Vec::new();

        for server in servers {
            let Some(hostname) = &server.hostname else {
                continue;
            };

            let service = match server.r#type {
                ServerType::Imap => DiscoveryService::Imap,
                ServerType::Pop3 => DiscoveryService::Pop3,
                ServerType::Smtp => DiscoveryService::Smtp,
            };

            let security = match server.socket_type {
                Some(SecurityType::Tls) | None => Security::Tls,
                Some(SecurityType::Starttls) => Security::Starttls,
                Some(SecurityType::Plain) => Security::Plain,
            };

            let Some(port) = server.port.or(default_port(service, security)) else {
                continue;
            };

            let mut auth = Vec::new();

            for method in &server.authentication {
                let method = match method {
                    AuthenticationType::PasswordCleartext
                    | AuthenticationType::PasswordEncrypted => DiscoveryAuthMethod::Password,
                    AuthenticationType::OAuth2 => {
                        let Some(oauth) = &config.oauth2 else {
                            continue;
                        };

                        DiscoveryAuthMethod::OauthAuthorizationCodeGrant {
                            authorization_endpoint: oauth.auth_url.clone(),
                            token_endpoint: oauth.token_url.clone(),
                            scope: Some(oauth.scope.clone()),
                        }
                    }
                    _ => continue,
                };

                if !auth.contains(&method) {
                    auth.push(method);
                }
            }

            configs.push(Self {
                service,
                endpoint: Endpoint::Tcp {
                    host: substitute(hostname, email),
                    port,
                    security,
                },
                username: server.username.as_deref().map(|u| substitute(u, email)),
                auth,
                source,
            });
        }

        configs
    }

    /// Flattens a PACC document into one config per advertised
    /// protocol. PACC mandates implicit TLS for the text protocols,
    /// so their configs use the well-known implicit-TLS ports.
    #[cfg(feature = "pacc")]
    pub fn from_pacc(config: &PaccConfig) -> Vec<Self> {
        let mut auth = Vec::new();

        if let Some(oauth) = &config.authentication.oauth_public {
            auth.push(DiscoveryAuthMethod::OauthIssuer(oauth.issuer.clone()));
        }

        if config.authentication.password == Some(true) {
            auth.push(DiscoveryAuthMethod::Password);
        }

        let protocols = &config.protocols;
        let mut configs = Vec::new();

        let tcp_protocols = [
            (DiscoveryService::Imap, &protocols.imap, 993),
            (DiscoveryService::Pop3, &protocols.pop3, 995),
            (DiscoveryService::Smtp, &protocols.smtp, 465),
            (DiscoveryService::Managesieve, &protocols.managesieve, 4190),
        ];

        for (service, protocol, port) in tcp_protocols {
            let Some(protocol) = protocol else {
                continue;
            };

            configs.push(Self {
                service,
                endpoint: Endpoint::Tcp {
                    host: protocol.host.clone(),
                    port,
                    security: Security::Tls,
                },
                username: None,
                auth: auth.clone(),
                source: ConfigSource::Pacc,
            });
        }

        let http_protocols = [
            (DiscoveryService::Jmap, &protocols.jmap),
            (DiscoveryService::Caldav, &protocols.caldav),
            (DiscoveryService::Carddav, &protocols.carddav),
            (DiscoveryService::Webdav, &protocols.webdav),
        ];

        for (service, protocol) in http_protocols {
            let Some(protocol) = protocol else {
                continue;
            };

            configs.push(Self {
                service,
                endpoint: Endpoint::Http(protocol.url.clone()),
                username: None,
                auth: auth.clone(),
                source: ConfigSource::Pacc,
            });
        }

        configs
    }

    /// Converts an RFC 6186 SRV report into configs. SRV records
    /// advertise no authentication data, so password login is
    /// assumed; `_imaps` maps to implicit TLS, `_imap` and
    /// `_submission` to STARTTLS.
    #[cfg(feature = "rfc6186")]
    pub fn from_srv(report: &SrvReport) -> Vec<Self> {
        let services = [
            (DiscoveryService::Imap, &report.imaps, Security::Tls),
            (DiscoveryService::Imap, &report.imap, Security::Starttls),
            (
                DiscoveryService::Smtp,
                &report.submission,
                Security::Starttls,
            ),
        ];

        let mut configs = Vec::new();

        for (service, record, security) in services {
            // NOTE: an SRV target of `.` means the service is
            // explicitly not available (RFC 2782); the target comes
            // in with its trailing dot already trimmed.
            let Some(SrvService { host, port, .. }) = record else {
                continue;
            };
            if host.is_empty() {
                continue;
            }

            configs.push(Self {
                service,
                endpoint: Endpoint::Tcp {
                    host: host.clone(),
                    port: *port,
                    security,
                },
                username: None,
                auth: vec![DiscoveryAuthMethod::Password],
                source: ConfigSource::Srv,
            });
        }

        configs
    }

    /// Wraps an RFC 6764 context root into a single config. DAV
    /// discovery advertises no authentication data, so password login
    /// is assumed.
    pub fn from_dav(service: DiscoveryService, url: impl ToString) -> Self {
        Self {
            service,
            endpoint: Endpoint::Http(url.to_string()),
            username: None,
            auth: vec![DiscoveryAuthMethod::Password],
            source: ConfigSource::Dav,
        }
    }

    /// Wraps an RFC 8620 JMAP session URL into a single config. The
    /// authentication methods derive from the schemes the session
    /// endpoint advertised on its unauthenticated 401 (`basic` means
    /// password login, `bearer` a bearer token); with no advertisement
    /// both are assumed, the bearer token first: the JMAP ecosystem is
    /// token-first (fastmail only accepts API tokens), and a wrongly
    /// assumed method fails visibly at the connection check while a
    /// missing one is a dead end.
    pub fn from_jmap(url: impl ToString, schemes: &[String]) -> Self {
        let mut auth = Vec::new();

        for scheme in schemes {
            match scheme.as_str() {
                "basic" => auth.push(DiscoveryAuthMethod::Password),
                "bearer" => auth.push(DiscoveryAuthMethod::Bearer),
                _ => (),
            }
        }

        if auth.is_empty() {
            auth = vec![DiscoveryAuthMethod::Bearer, DiscoveryAuthMethod::Password];
        }

        Self {
            service: DiscoveryService::Jmap,
            endpoint: Endpoint::Http(url.to_string()),
            username: None,
            auth,
            source: ConfigSource::Jmap,
        }
    }
}

/// A PIM service kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryService {
    Imap,
    Pop3,
    Smtp,
    Jmap,
    Caldav,
    Carddav,
    Webdav,
    Managesieve,
}

/// Where to reach a service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Endpoint {
    /// Text protocol endpoint (IMAP, POP3, SMTP, ManageSieve).
    Tcp {
        host: String,
        port: u16,
        security: Security,
    },
    /// HTTP endpoint (JMAP, CalDAV, CardDAV, WebDAV).
    Http(String),
}

impl Endpoint {
    /// Reports whether two endpoints reach the same service: byte
    /// equality, or normalized-URL equality for HTTP endpoints, so
    /// mechanisms disagreeing only on a trailing slash or an explicit
    /// default port still merge.
    pub fn equivalent(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }

        match (self, other) {
            (Self::Http(a), Self::Http(b)) => match (Url::parse(a), Url::parse(b)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            },
            _ => false,
        }
    }

    /// Reports whether this HTTP endpoint's host is a subdomain of the
    /// other's: the mark of a rotated backend behind a provider's
    /// stable service name (fastmail's SRV records answer with
    /// `dNNNNNN.carddav.fastmail.com` shards under the
    /// `carddav.fastmail.com` its own configuration document
    /// advertises).
    pub fn subdomain_of(&self, other: &Self) -> bool {
        let (Self::Http(a), Self::Http(b)) = (self, other) else {
            return false;
        };
        let (Ok(a), Ok(b)) = (Url::parse(a), Url::parse(b)) else {
            return false;
        };
        let (Some(a), Some(b)) = (a.host_str(), b.host_str()) else {
            return false;
        };

        a.len() > b.len() && a.ends_with(b) && a.as_bytes()[a.len() - b.len() - 1] == b'.'
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use crate::compose::types::{
        ConfigSource, DiscoveryAuthMethod, DiscoveryService, DiscoveryServiceConfig, Endpoint,
    };

    #[test]
    fn probed_schemes_beat_account_level_claims() {
        let mut config = DiscoveryServiceConfig {
            service: DiscoveryService::Jmap,
            endpoint: Endpoint::Http("https://api.example.com/jmap/session".to_string()),
            username: None,
            auth: vec![
                DiscoveryAuthMethod::OauthIssuer("https://api.example.com".to_string()),
                DiscoveryAuthMethod::Password,
            ],
            source: ConfigSource::Pacc,
        };

        // The endpoint advertises bearer only: the account-level
        // password claim goes, the OAuth issuer stays.
        config.refine_auth(&["bearer".to_string()]);
        assert_eq!(
            config.auth,
            vec![
                DiscoveryAuthMethod::Bearer,
                DiscoveryAuthMethod::OauthIssuer("https://api.example.com".to_string()),
            ],
        );

        // Unknown schemes leave the config as discovered.
        config.refine_auth(&["negotiate".to_string()]);
        assert!(config.auth.contains(&DiscoveryAuthMethod::Bearer));
    }

    #[test]
    fn http_endpoints_compare_normalized() {
        let bare = Endpoint::Http("https://carddav.example.com".to_string());
        let slash = Endpoint::Http("https://carddav.example.com/".to_string());
        let port = Endpoint::Http("https://carddav.example.com:443/".to_string());
        let other = Endpoint::Http("https://carddav.example.com/dav".to_string());

        assert!(bare.equivalent(&slash));
        assert!(bare.equivalent(&port));
        assert!(!bare.equivalent(&other));
    }

    #[test]
    fn subdomain_marks_a_rotated_backend() {
        let parent = Endpoint::Http("https://carddav.example.com".to_string());
        let shard = Endpoint::Http("https://d063023.carddav.example.com/dav".to_string());
        let sibling = Endpoint::Http("https://caldav.example.com".to_string());
        let lookalike = Endpoint::Http("https://evilcarddav.example.com".to_string());

        assert!(shard.subdomain_of(&parent));
        assert!(!parent.subdomain_of(&shard));
        assert!(!sibling.subdomain_of(&parent));
        assert!(!lookalike.subdomain_of(&parent));
    }
}

/// Transport security of a TCP service endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Security {
    Plain,
    Starttls,
    Tls,
}

/// How a client can authenticate against a service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryAuthMethod {
    /// Username and password login (possibly an app password).
    Password,

    /// Bearer token (RFC 6750), e.g. a provider-issued API token.
    Bearer,

    /// OAuth 2.0 authorization code grant (RFC 6749 §4.1).
    OauthAuthorizationCodeGrant {
        authorization_endpoint: String,
        token_endpoint: String,
        scope: Option<String>,
    },

    /// OAuth 2.0 device authorization grant (RFC 8628).
    OauthDeviceAuthorizationGrant {
        device_authorization_endpoint: String,
        token_endpoint: String,
        scope: Option<String>,
    },

    /// OAuth 2.0 with grant types not known yet: the issuer's RFC
    /// 8414 authorization server metadata lists the endpoints and
    /// supported grants.
    OauthIssuer(String),
}

/// The mechanism that produced a config.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfigSource {
    /// A fixed provider rule (domain or MX match).
    Provider(Provider),
    /// PACC discovery.
    Pacc,
    /// The autoconfig ISP main URL.
    IspMain,
    /// The autoconfig ISP fallback URL.
    IspFallback,
    /// The autoconfig document behind the mailconf TXT redirect.
    Mailconf,
    /// The Thunderbird ISPDB.
    Ispdb,
    /// RFC 6186 SRV records.
    Srv,
    /// RFC 6764 CalDAV/CardDAV resolve.
    Dav,
    /// RFC 8620 JMAP resolve.
    Jmap,
}

/// Substitutes the Mozilla autoconfig placeholders (%EMAILADDRESS%,
/// %EMAILLOCALPART%, %EMAILDOMAIN%) in a hostname or username value.
#[cfg(feature = "autoconfig")]
fn substitute(value: &str, email: &str) -> String {
    let (local_part, domain) = email.split_once('@').unwrap_or((email, ""));

    value
        .replace("%EMAILADDRESS%", email)
        .replace("%EMAILLOCALPART%", local_part)
        .replace("%EMAILDOMAIN%", domain)
}

/// Returns the well-known port for a service and security
/// combination, used when a mechanism omits the port.
#[cfg(feature = "autoconfig")]
fn default_port(service: DiscoveryService, security: Security) -> Option<u16> {
    match (service, security) {
        (DiscoveryService::Imap, Security::Tls) => Some(993),
        (DiscoveryService::Imap, _) => Some(143),
        (DiscoveryService::Pop3, Security::Tls) => Some(995),
        (DiscoveryService::Pop3, _) => Some(110),
        (DiscoveryService::Smtp, Security::Tls) => Some(465),
        (DiscoveryService::Smtp, Security::Starttls) => Some(587),
        (DiscoveryService::Smtp, Security::Plain) => Some(25),
        (DiscoveryService::Managesieve, _) => Some(4190),
        _ => None,
    }
}
