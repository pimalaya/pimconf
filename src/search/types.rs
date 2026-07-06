//! # Unified search types
//!
//! The search module reduces every discovery mechanism to one common
//! output: a list of [`ServiceConfig`], each describing one way to
//! reach one service (endpoint, login, authentication methods),
//! tagged with the mechanism that produced it. Conversion helpers on
//! [`ServiceConfig`] flatten each mechanism's native document into
//! that shape.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};

use crate::{
    autoconfig::types::{AuthenticationType, Autoconfig, SecurityType, ServerType},
    pacc::types::PaccConfig,
    rfc6186::types::{SrvReport, SrvService},
    search::providers::Provider,
};

/// One discovered way to use one service: where to connect, how to
/// authenticate, and which mechanism found it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    /// The service this config describes.
    pub service: Service,

    /// Where to reach the service.
    pub endpoint: Endpoint,

    /// The login to present, when the mechanism advertises one
    /// (autoconfig placeholders already substituted).
    pub username: Option<String>,

    /// The authentication methods the service accepts.
    pub auth: Vec<AuthMethod>,

    /// The mechanism that produced this config.
    pub source: ConfigSource,
}

impl ServiceConfig {
    /// Flattens a Mozilla autoconfig document into one config per
    /// incoming/outgoing server. Servers without a hostname are
    /// skipped; a missing port falls back to the well-known port of
    /// the service and security combination.
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
                ServerType::Imap => Service::Imap,
                ServerType::Pop3 => Service::Pop3,
                ServerType::Smtp => Service::Smtp,
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
                    | AuthenticationType::PasswordEncrypted => AuthMethod::Password,
                    AuthenticationType::OAuth2 => {
                        let Some(oauth) = &config.oauth2 else {
                            continue;
                        };

                        AuthMethod::OauthAuthorizationCodeGrant {
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
    pub fn from_pacc(config: &PaccConfig) -> Vec<Self> {
        let mut auth = Vec::new();

        if let Some(oauth) = &config.authentication.oauth_public {
            auth.push(AuthMethod::OauthIssuer(oauth.issuer.clone()));
        }

        if config.authentication.password == Some(true) {
            auth.push(AuthMethod::Password);
        }

        let protocols = &config.protocols;
        let mut configs = Vec::new();

        let tcp_protocols = [
            (Service::Imap, &protocols.imap, 993),
            (Service::Pop3, &protocols.pop3, 995),
            (Service::Smtp, &protocols.smtp, 465),
            (Service::Managesieve, &protocols.managesieve, 4190),
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
            (Service::Jmap, &protocols.jmap),
            (Service::Caldav, &protocols.caldav),
            (Service::Carddav, &protocols.carddav),
            (Service::Webdav, &protocols.webdav),
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
    pub fn from_srv(report: &SrvReport) -> Vec<Self> {
        let services = [
            (Service::Imap, &report.imaps, Security::Tls),
            (Service::Imap, &report.imap, Security::Starttls),
            (Service::Smtp, &report.submission, Security::Starttls),
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
                auth: vec![AuthMethod::Password],
                source: ConfigSource::Srv,
            });
        }

        configs
    }

    /// Wraps an RFC 6764 context root into a single config. DAV
    /// discovery advertises no authentication data, so password login
    /// is assumed.
    pub fn from_dav(service: Service, url: impl ToString) -> Self {
        Self {
            service,
            endpoint: Endpoint::Http(url.to_string()),
            username: None,
            auth: vec![AuthMethod::Password],
            source: ConfigSource::Dav,
        }
    }

    /// Wraps an RFC 8620 JMAP session URL into a single config. The
    /// authentication methods derive from the schemes the session
    /// endpoint advertised on its unauthenticated 401 (`basic` means
    /// password login, `bearer` a bearer token); with no advertisement
    /// both are assumed.
    pub fn from_jmap(url: impl ToString, schemes: &[String]) -> Self {
        let mut auth = Vec::new();

        for scheme in schemes {
            match scheme.as_str() {
                "basic" => auth.push(AuthMethod::Password),
                "bearer" => auth.push(AuthMethod::Bearer),
                _ => (),
            }
        }

        if auth.is_empty() {
            auth = vec![AuthMethod::Password, AuthMethod::Bearer];
        }

        Self {
            service: Service::Jmap,
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
pub enum Service {
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
pub enum AuthMethod {
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
fn substitute(value: &str, email: &str) -> String {
    let (local_part, domain) = email.split_once('@').unwrap_or((email, ""));

    value
        .replace("%EMAILADDRESS%", email)
        .replace("%EMAILLOCALPART%", local_part)
        .replace("%EMAILDOMAIN%", domain)
}

/// Returns the well-known port for a service and security
/// combination, used when a mechanism omits the port.
fn default_port(service: Service, security: Security) -> Option<u16> {
    match (service, security) {
        (Service::Imap, Security::Tls) => Some(993),
        (Service::Imap, _) => Some(143),
        (Service::Pop3, Security::Tls) => Some(995),
        (Service::Pop3, _) => Some(110),
        (Service::Smtp, Security::Tls) => Some(465),
        (Service::Smtp, Security::Starttls) => Some(587),
        (Service::Smtp, Security::Plain) => Some(25),
        (Service::Managesieve, _) => Some(4190),
        _ => None,
    }
}
