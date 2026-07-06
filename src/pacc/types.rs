//! # PACC discovery types
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaccConfig {
    pub protocols: Protocols,
    pub authentication: Authentication,
    pub info: Info,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Protocols {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmap: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caldav: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carddav: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdav: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap: Option<TextProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<TextProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<TextProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managesieve: Option<TextProtocol>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpProtocol {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TextProtocol {
    pub host: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    #[serde(rename = "oauth-public")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_public: Option<OauthPublic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthPublic {
    pub issuer: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub provider: Provider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<Help>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Vec<Logo>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Logo {
    pub url: String,
    #[serde(rename = "content-type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Help {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}

impl fmt::Display for PaccConfig {
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
