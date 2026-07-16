//! # Autoconfig configuration document
//!
//! `serde` representation of the Mozilla [Autoconfiguration] XML
//! configuration document. Containers default to camelCase via
//! `#[serde(rename_all = "camelCase")]`; spec-flavoured names that
//! diverge from camelCase (`oAuth2`, `STARTTLS`, `SSL`,
//! `password-cleartext`, `authURL`, `descr`, …) are accepted on
//! deserialize via `#[serde(alias = "...")]` so XML parsing matches
//! the spec while JSON serialization stays clean camelCase and
//! round-trips JSON cleanly.
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat

use core::fmt;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

/// Root `<clientConfig>` document returned by an autoconfig endpoint.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryAutoconfig {
    /// Autoconfig schema version (e.g. `"1.1"`).
    #[serde(alias = "@version")]
    pub version: String,
    /// Email provider settings block (`<emailProvider>`).
    pub email_provider: DiscoveryEmailProvider,
    /// Optional OAuth 2.0 parameters for the provider (`<oAuth2>`).
    #[serde(alias = "oAuth2")]
    pub oauth2: Option<DiscoveryOAuth2Config>,
}

/// Email provider descriptor (`<emailProvider>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryEmailProvider {
    /// Unique provider identifier (e.g. `"gmail.com"`).
    #[serde(alias = "@id")]
    pub id: String,
    /// Domain names served by this provider.
    #[serde(default)]
    pub domain: Vec<String>,
    /// Human-readable provider name shown in UI.
    pub display_name: Option<String>,
    /// Abbreviated provider name for compact UI contexts.
    pub display_short_name: Option<String>,
    /// Incoming mail server configurations (IMAP or POP3).
    #[serde(default)]
    pub incoming_server: Vec<DiscoveryServer>,
    /// Outgoing mail server configurations (SMTP).
    #[serde(default)]
    pub outgoing_server: Vec<DiscoveryServer>,
    /// Links to provider setup documentation.
    #[serde(default)]
    pub documentation: Vec<DiscoveryDocumentation>,
}

/// Incoming or outgoing mail server entry (`<incomingServer>` /
/// `<outgoingServer>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryServer {
    /// Protocol spoken by this server (IMAP, POP3, or SMTP).
    #[serde(alias = "@type")]
    pub r#type: DiscoveryServerType,
    /// DNS hostname of the server.
    pub hostname: Option<String>,
    /// TCP port number.
    pub port: Option<u16>,
    /// Transport security layer to use when connecting.
    #[serde(default, deserialize_with = "text_enum::option::deserialize")]
    pub socket_type: Option<DiscoverySecurityType>,
    /// Login username template (may contain `%EMAILADDRESS%` etc.).
    pub username: Option<String>,
    /// Ordered list of accepted authentication mechanisms.
    #[serde(default, deserialize_with = "text_enum::vec::deserialize")]
    pub authentication: Vec<DiscoveryAuthenticationType>,
    /// POP3-specific settings; present only when `type` is `pop3`.
    pub pop3: Option<DiscoveryPop3Config>,
}

/// Mail protocol used by a server entry.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryServerType {
    /// Post Office Protocol version 3.
    Pop3,
    /// Internet Message Access Protocol.
    Imap,
    /// Simple Mail Transfer Protocol.
    Smtp,
}

/// Transport security layer applied to a server connection.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoverySecurityType {
    /// Unencrypted connection.
    Plain,
    /// Upgrade to TLS via the STARTTLS command after connecting.
    #[serde(alias = "STARTTLS")]
    Starttls,
    /// Implicit TLS from the first byte (TLS/SSL wrapper).
    #[serde(alias = "SSL")]
    Tls,
}

/// Authentication mechanism supported by a server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryAuthenticationType {
    /// Plain-text password sent in the clear (PLAIN/LOGIN).
    #[serde(alias = "password-cleartext")]
    PasswordCleartext,
    /// Password transmitted in an encrypted form (CRAM-MD5 etc.).
    #[serde(alias = "password-encrypted")]
    PasswordEncrypted,
    /// Microsoft NTLM challenge-response authentication.
    #[serde(alias = "NTLM")]
    Ntlm,
    /// Kerberos/GSSAPI authentication.
    #[serde(alias = "GSAPI")]
    GsApi,
    /// Server authenticates the client by its IP address; no
    /// credentials required.
    #[serde(alias = "client-IP-address")]
    ClientIPAddress,
    /// Mutual authentication via a TLS client certificate.
    #[serde(alias = "TLS-client-cert")]
    TlsClientCert,
    /// Bearer-token authentication via OAuth 2.0.
    #[serde(alias = "OAuth2")]
    OAuth2,
    /// No authentication required.
    None,
}

/// POP3-specific server options (`<pop3>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryPop3Config {
    /// Whether retrieved messages are kept on the server.
    pub leave_messages_on_server: Option<bool>,
    /// Whether new-mail notifications (biff) trigger a download.
    pub download_on_biff: Option<bool>,
    /// How many days messages are retained on the server before
    /// deletion.
    pub days_to_leave_messages_on_server: Option<u64>,
    /// Periodic polling interval for new mail.
    pub check_interval: Option<DiscoveryCheckInterval>,
}

/// Mail-check polling interval (`<checkInterval>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryCheckInterval {
    /// Polling frequency in minutes.
    #[serde(alias = "@minutes")]
    pub minutes: Option<u64>,
}

/// Link to provider setup documentation (`<documentation>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryDocumentation {
    /// URL of the documentation page.
    #[serde(alias = "@url")]
    pub url: String,
    /// Per-language descriptions of the linked page.
    #[serde(default, alias = "descr")]
    pub descriptions: Vec<DiscoveryDescription>,
}

/// Localised text description of a documentation link (`<descr>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryDescription {
    /// BCP 47 language tag (e.g. `"en"`, `"fr"`).
    #[serde(alias = "@lang")]
    pub lang: Option<String>,
    /// Human-readable description text in the given language.
    #[serde(alias = "#text")]
    pub text: String,
}

/// OAuth 2.0 parameters for the provider (`<oAuth2>`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryOAuth2Config {
    /// OAuth 2.0 issuer identifier (typically the provider's domain).
    pub issuer: String,
    /// Space-separated list of OAuth 2.0 scopes to request.
    pub scope: String,
    /// Authorization endpoint URL.
    #[serde(alias = "authURL")]
    pub auth_url: String,
    /// Token endpoint URL.
    #[serde(alias = "tokenURL")]
    pub token_url: String,
}

impl fmt::Display for DiscoveryAutoconfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = &self.email_provider;

        match (&p.display_name, &p.display_short_name) {
            (Some(n), Some(s)) => writeln!(f, "{n} ({s})")?,
            (Some(n), None) | (None, Some(n)) => writeln!(f, "{n}")?,
            (None, None) => writeln!(f, "{}", p.id)?,
        }

        if !p.domain.is_empty() {
            writeln!(f, "{}", p.domain.join(", "))?;
        }

        if !p.incoming_server.is_empty() {
            writeln!(f, "\nIncoming")?;
            for s in &p.incoming_server {
                writeln!(f, "  {s}")?;
            }
        }

        if !p.outgoing_server.is_empty() {
            writeln!(f, "\nOutgoing")?;
            for s in &p.outgoing_server {
                writeln!(f, "  {s}")?;
            }
        }

        if let Some(o) = &self.oauth2 {
            writeln!(f, "\nOAuth2")?;
            writeln!(f, "{o}")?;
        }

        if !p.documentation.is_empty() {
            writeln!(f, "\nDocumentation")?;
            for d in &p.documentation {
                writeln!(f, "  {d}")?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for DiscoveryServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_label = match self.r#type {
            DiscoveryServerType::Imap => "imap",
            DiscoveryServerType::Pop3 => "pop3",
            DiscoveryServerType::Smtp => "smtp",
        };
        write!(
            f,
            "{type_label:6}{}",
            self.hostname.as_deref().unwrap_or("?")
        )?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(sec) = &self.socket_type {
            let label = match sec {
                DiscoverySecurityType::Plain => "Plain",
                DiscoverySecurityType::Starttls => "STARTTLS",
                DiscoverySecurityType::Tls => "SSL",
            };
            write!(f, " ({label})")?;
        }

        let mut first = true;
        for auth in &self.authentication {
            f.write_str(if first { " " } else { ", " })?;
            first = false;
            f.write_str(match auth {
                DiscoveryAuthenticationType::PasswordCleartext => "password-cleartext",
                DiscoveryAuthenticationType::PasswordEncrypted => "password-encrypted",
                DiscoveryAuthenticationType::Ntlm => "NTLM",
                DiscoveryAuthenticationType::GsApi => "GSAPI",
                DiscoveryAuthenticationType::ClientIPAddress => "client-IP-address",
                DiscoveryAuthenticationType::TlsClientCert => "TLS-client-cert",
                DiscoveryAuthenticationType::OAuth2 => "OAuth2",
                DiscoveryAuthenticationType::None => "none",
            })?;
        }

        Ok(())
    }
}

impl fmt::Display for DiscoveryDocumentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.descriptions.first() {
            Some(DiscoveryDescription {
                lang: Some(lang),
                text,
            }) => write!(f, "{} ({lang}: {text})", self.url),
            Some(DiscoveryDescription { lang: None, text }) => write!(f, "{} {text}", self.url),
            None => write!(f, "{}", self.url),
        }
    }
}

impl fmt::Display for DiscoveryOAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  {:11}{}", "Issuer", self.issuer)?;
        writeln!(f, "  {:11}{}", "Scope", self.scope)?;
        writeln!(f, "  {:11}{}", "Auth URL", self.auth_url)?;
        writeln!(f, "  {:11}{}", "Token URL", self.token_url)
    }
}

// HACK: serde-xml-rs 0.8 wraps the text content of a leaf element in
// a `#text` field. Unit enums deserialized from `<el>VARIANT</el>`
// need a wrapper that unwraps that field before passing the variant
// name to serde. These helpers are deserialize-only so JSON
// serialization stays clean (`"socketType": "tls"` instead of
// `{"#text": "tls"}`).
mod text_enum {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Text<T> {
        #[serde(rename = "#text")]
        text: T,
    }

    pub mod option {
        use serde::{Deserialize, Deserializer};

        use crate::autoconfig::config::text_enum::Text;

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            Text::<T>::deserialize(deserializer).map(|t| Some(t.text))
        }
    }

    pub mod vec {
        use alloc::vec::Vec;

        use serde::{Deserialize, Deserializer};

        use crate::autoconfig::config::text_enum::Text;

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            Vec::<Text<T>>::deserialize(deserializer)
                .map(|v| v.into_iter().map(|t| t.text).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::autoconfig::config::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="example.com">
    <domain>example.com</domain>
    <domain>example.org</domain>
    <displayName>Example Mail</displayName>
    <displayShortName>Example</displayShortName>
    <incomingServer type="imap">
      <hostname>imap.example.com</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>OAuth2</authentication>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>pop.example.com</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-encrypted</authentication>
      <pop3>
        <leaveMessagesOnServer>true</leaveMessagesOnServer>
        <downloadOnBiff>true</downloadOnBiff>
        <daysToLeaveMessagesOnServer>14</daysToLeaveMessagesOnServer>
        <checkInterval minutes="10"/>
      </pop3>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.com</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
    <documentation url="https://example.com/help">
      <descr lang="en">English help</descr>
      <descr lang="fr">Aide en français</descr>
    </documentation>
  </emailProvider>
  <oAuth2>
    <issuer>example.com</issuer>
    <scope>https://mail.example.com/</scope>
    <authURL>https://example.com/oauth2/auth</authURL>
    <tokenURL>https://example.com/oauth2/token</tokenURL>
  </oAuth2>
</clientConfig>
"#;

    #[test]
    fn parses_full_clientconfig() {
        let cfg: DiscoveryAutoconfig =
            serde_xml_rs::from_str(SAMPLE).expect("autoconfig XML should deserialize");

        assert_eq!(cfg.version, "1.1");

        let p = &cfg.email_provider;
        assert_eq!(p.id, "example.com");
        assert_eq!(p.domain, vec!["example.com", "example.org"]);
        assert_eq!(p.display_name.as_deref(), Some("Example Mail"));
        assert_eq!(p.display_short_name.as_deref(), Some("Example"));

        assert_eq!(p.incoming_server.len(), 2);

        let imap = &p.incoming_server[0];
        assert!(matches!(imap.r#type, DiscoveryServerType::Imap));
        assert_eq!(imap.hostname.as_deref(), Some("imap.example.com"));
        assert_eq!(imap.port, Some(993));
        assert!(matches!(imap.socket_type, Some(DiscoverySecurityType::Tls)));
        assert_eq!(imap.username.as_deref(), Some("%EMAILADDRESS%"));
        assert_eq!(imap.authentication.len(), 2);
        assert!(matches!(
            imap.authentication[0],
            DiscoveryAuthenticationType::OAuth2
        ));
        assert!(matches!(
            imap.authentication[1],
            DiscoveryAuthenticationType::PasswordCleartext
        ));
        assert!(imap.pop3.is_none());

        let pop = &p.incoming_server[1];
        assert!(matches!(pop.r#type, DiscoveryServerType::Pop3));
        assert!(matches!(pop.socket_type, Some(DiscoverySecurityType::Tls)));
        assert!(matches!(
            pop.authentication[0],
            DiscoveryAuthenticationType::PasswordEncrypted
        ));
        let pop_cfg = pop.pop3.as_ref().expect("pop3 block");
        assert_eq!(pop_cfg.leave_messages_on_server, Some(true));
        assert_eq!(pop_cfg.download_on_biff, Some(true));
        assert_eq!(pop_cfg.days_to_leave_messages_on_server, Some(14));
        assert_eq!(
            pop_cfg.check_interval.as_ref().and_then(|c| c.minutes),
            Some(10)
        );

        assert_eq!(p.outgoing_server.len(), 1);
        let smtp = &p.outgoing_server[0];
        assert!(matches!(smtp.r#type, DiscoveryServerType::Smtp));
        assert!(matches!(
            smtp.socket_type,
            Some(DiscoverySecurityType::Starttls)
        ));

        assert_eq!(p.documentation.len(), 1);
        let doc = &p.documentation[0];
        assert_eq!(doc.url, "https://example.com/help");
        assert_eq!(doc.descriptions.len(), 2);
        assert_eq!(doc.descriptions[0].lang.as_deref(), Some("en"));
        assert_eq!(doc.descriptions[0].text, "English help");
        assert_eq!(doc.descriptions[1].lang.as_deref(), Some("fr"));
        assert_eq!(doc.descriptions[1].text, "Aide en français");

        let oauth = cfg.oauth2.as_ref().expect("oauth2 block");
        assert_eq!(oauth.issuer, "example.com");
        assert_eq!(oauth.scope, "https://mail.example.com/");
        assert_eq!(oauth.auth_url, "https://example.com/oauth2/auth");
        assert_eq!(oauth.token_url, "https://example.com/oauth2/token");
    }

    // NOTE: minimal real-world shape: single IMAP + SMTP, no
    // documentation, no OAuth2. Catches regressions where optional
    // sections silently require defaulted structure.
    #[test]
    fn parses_minimal_clientconfig() {
        let xml = r#"<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="posteo.de">
    <domain>posteo.de</domain>
    <displayName>Posteo</displayName>
    <displayShortName>Posteo</displayShortName>
    <incomingServer type="imap">
      <hostname>posteo.de</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>posteo.de</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"#;

        let cfg: DiscoveryAutoconfig = serde_xml_rs::from_str(xml).unwrap();
        assert!(cfg.oauth2.is_none());
        assert!(cfg.email_provider.documentation.is_empty());
        assert_eq!(cfg.email_provider.incoming_server.len(), 1);
        assert_eq!(cfg.email_provider.outgoing_server.len(), 1);
    }

    // NOTE: lowercase variant identifiers (no SSL/STARTTLS aliases)
    // must still work via `rename_all = "camelCase"`.
    #[test]
    fn accepts_camelcase_variants() {
        let xml = r#"<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="x">
    <domain>x</domain>
    <incomingServer type="imap">
      <hostname>imap.x</hostname>
      <port>143</port>
      <socketType>starttls</socketType>
      <authentication>none</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.x</hostname>
      <port>25</port>
      <socketType>plain</socketType>
      <authentication>none</authentication>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"#;

        let cfg: DiscoveryAutoconfig = serde_xml_rs::from_str(xml).unwrap();
        assert!(matches!(
            cfg.email_provider.incoming_server[0].socket_type,
            Some(DiscoverySecurityType::Starttls)
        ));
        assert!(matches!(
            cfg.email_provider.outgoing_server[0].socket_type,
            Some(DiscoverySecurityType::Plain)
        ));
        assert!(matches!(
            cfg.email_provider.incoming_server[0].authentication[0],
            DiscoveryAuthenticationType::None
        ));
    }
}
