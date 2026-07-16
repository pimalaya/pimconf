//! # PACC configuration document
//!
//! `serde` representation of the JSON configuration document defined
//! by [draft-ietf-mailmaint-pacc-02]. Containers default to camelCase
//! via `#[serde(rename_all = "camelCase")]`; the few kebab-case keys
//! the draft uses on the wire (`oauth-public`, `content-type`) get a
//! field-level `#[serde(rename = ...)]` override, both directions.
//!
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02

use core::fmt;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

/// Top-level PACC configuration document fetched from the well-known
/// URL and verified against the DNS digest.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryPaccConfig {
    /// Protocol endpoints advertised by this provider.
    pub protocols: DiscoveryProtocols,
    /// Authentication methods supported by this provider.
    pub authentication: DiscoveryAuthentication,
    /// Human-readable provider metadata and support links.
    pub info: DiscoveryInfo,
}

/// Set of protocol endpoints the provider supports; absent fields mean
/// the protocol is not offered.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryProtocols {
    /// JMAP service base URL (RFC 8620).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmap: Option<DiscoveryHttpProtocol>,
    /// CalDAV service URL (RFC 4791).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caldav: Option<DiscoveryHttpProtocol>,
    /// CardDAV service URL (RFC 6352).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carddav: Option<DiscoveryHttpProtocol>,
    /// Generic WebDAV service URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdav: Option<DiscoveryHttpProtocol>,
    /// IMAP server hostname (RFC 9051).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap: Option<DiscoveryTextProtocol>,
    /// POP3 server hostname (RFC 1939).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<DiscoveryTextProtocol>,
    /// SMTP submission hostname (RFC 6409).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<DiscoveryTextProtocol>,
    /// ManageSieve server hostname (RFC 5804).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managesieve: Option<DiscoveryTextProtocol>,
}

/// Endpoint descriptor for an HTTP-based protocol (JMAP, CalDAV,
/// CardDAV, WebDAV).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryHttpProtocol {
    /// Absolute HTTPS base URL for the service.
    pub url: String,
}

/// Endpoint descriptor for a text-based protocol (IMAP, POP3, SMTP,
/// ManageSieve).
#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryTextProtocol {
    /// Hostname of the server.
    pub host: String,
}

/// Authentication methods supported by the provider.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryAuthentication {
    /// OAuth 2.0 public-client configuration; present when the
    /// provider supports OAuth without a client secret (wire key:
    /// `oauth-public`).
    #[serde(rename = "oauth-public")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_public: Option<DiscoveryOauthPublic>,
    /// `true` when the provider accepts password-based authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
}

/// OAuth 2.0 public-client parameters; the client fetches server
/// metadata from the issuer URL per RFC 8414.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryOauthPublic {
    /// OAuth 2.0 issuer URL used to discover the authorization server
    /// metadata (RFC 8414 / RFC 9728).
    pub issuer: String,
}

/// Human-readable provider metadata included in the PACC document.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryInfo {
    /// Identity and branding information for the provider.
    pub provider: DiscoveryProvider,
    /// Optional support and documentation links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<DiscoveryHelp>,
}

/// Identity and branding of the email/PIM service provider.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryProvider {
    /// Full display name of the provider (e.g. `"Example Mail"`).
    pub name: String,
    /// Abbreviated name suitable for constrained UI space.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    /// One or more provider logo images at different sizes or formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Vec<DiscoveryLogo>>,
}

/// A single provider logo image.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryLogo {
    /// Absolute URL pointing to the logo image resource.
    pub url: String,
    /// MIME type of the image (wire key: `content-type`); e.g.
    /// `"image/png"` or `"image/svg+xml"`.
    #[serde(rename = "content-type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Support and documentation resources offered by the provider.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryHelp {
    /// URL of the end-user documentation page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    /// URL of the developer or API documentation page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<String>,
    /// One or more contact URLs or email addresses for support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}

impl fmt::Display for DiscoveryPaccConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let provider = &self.info.provider;
        match &provider.short_name {
            Some(short) => writeln!(f, "{} ({short})", provider.name)?,
            None => writeln!(f, "{}", provider.name)?,
        }

        let p = &self.protocols;
        let any_proto = p.jmap.is_some()
            || p.caldav.is_some()
            || p.carddav.is_some()
            || p.webdav.is_some()
            || p.imap.is_some()
            || p.pop3.is_some()
            || p.smtp.is_some()
            || p.managesieve.is_some();

        if any_proto {
            writeln!(f, "\nProtocols")?;
            if let Some(x) = &p.jmap {
                writeln!(f, "  {:15}{}", "jmap", x.url)?;
            }
            if let Some(x) = &p.caldav {
                writeln!(f, "  {:15}{}", "caldav", x.url)?;
            }
            if let Some(x) = &p.carddav {
                writeln!(f, "  {:15}{}", "carddav", x.url)?;
            }
            if let Some(x) = &p.webdav {
                writeln!(f, "  {:15}{}", "webdav", x.url)?;
            }
            if let Some(x) = &p.imap {
                writeln!(f, "  {:15}{}", "imap", x.host)?;
            }
            if let Some(x) = &p.pop3 {
                writeln!(f, "  {:15}{}", "pop3", x.host)?;
            }
            if let Some(x) = &p.smtp {
                writeln!(f, "  {:15}{}", "smtp", x.host)?;
            }
            if let Some(x) = &p.managesieve {
                writeln!(f, "  {:15}{}", "managesieve", x.host)?;
            }
        }

        let auth = &self.authentication;
        if auth.oauth_public.is_some() || auth.password == Some(true) {
            writeln!(f, "\nAuthentication")?;
            if let Some(o) = &auth.oauth_public {
                writeln!(f, "  {:15}{}", "OAuth", o.issuer)?;
            }
            if auth.password == Some(true) {
                writeln!(f, "  {:15}supported", "Password")?;
            }
        }

        if let Some(help) = &self.info.help {
            let has_contact = help.contact.as_ref().is_some_and(|c| !c.is_empty());
            if help.documentation.is_some() || help.developer.is_some() || has_contact {
                writeln!(f, "\nHelp")?;
                if let Some(d) = &help.documentation {
                    writeln!(f, "  {:15}{d}", "Documentation")?;
                }
                if let Some(d) = &help.developer {
                    writeln!(f, "  {:15}{d}", "Developer")?;
                }
                if let Some(c) = &help.contact {
                    if !c.is_empty() {
                        writeln!(f, "  {:15}{}", "Contact", c.join(", "))?;
                    }
                }
            }
        }

        Ok(())
    }
}
