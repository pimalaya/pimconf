//! # Autoconfig discovery types
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Autoconfig {
    #[serde(alias = "@version")]
    pub version: String,
    pub email_provider: EmailProvider,
    #[serde(alias = "oAuth2")]
    pub oauth2: Option<OAuth2Config>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailProvider {
    #[serde(alias = "@id")]
    pub id: String,
    #[serde(default)]
    pub domain: Vec<String>,
    pub display_name: Option<String>,
    pub display_short_name: Option<String>,
    #[serde(default)]
    pub incoming_server: Vec<Server>,
    #[serde(default)]
    pub outgoing_server: Vec<Server>,
    #[serde(default)]
    pub documentation: Vec<Documentation>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    #[serde(alias = "@type")]
    pub r#type: ServerType,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    #[serde(default, deserialize_with = "text_enum::option::deserialize")]
    pub socket_type: Option<SecurityType>,
    pub username: Option<String>,
    #[serde(default, deserialize_with = "text_enum::vec::deserialize")]
    pub authentication: Vec<AuthenticationType>,
    pub pop3: Option<Pop3Config>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServerType {
    Pop3,
    Imap,
    Smtp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityType {
    Plain,
    #[serde(alias = "STARTTLS")]
    Starttls,
    #[serde(alias = "SSL")]
    Tls,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationType {
    #[serde(alias = "password-cleartext")]
    PasswordCleartext,
    #[serde(alias = "password-encrypted")]
    PasswordEncrypted,
    #[serde(alias = "NTLM")]
    Ntlm,
    #[serde(alias = "GSAPI")]
    GsApi,
    #[serde(alias = "client-IP-address")]
    ClientIPAddress,
    #[serde(alias = "TLS-client-cert")]
    TlsClientCert,
    #[serde(alias = "OAuth2")]
    OAuth2,
    None,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pop3Config {
    pub leave_messages_on_server: Option<bool>,
    pub download_on_biff: Option<bool>,
    pub days_to_leave_messages_on_server: Option<u64>,
    pub check_interval: Option<CheckInterval>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckInterval {
    #[serde(alias = "@minutes")]
    pub minutes: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Documentation {
    #[serde(alias = "@url")]
    pub url: String,
    #[serde(default, alias = "descr")]
    pub descriptions: Vec<Description>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    #[serde(alias = "@lang")]
    pub lang: Option<String>,
    #[serde(alias = "#text")]
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Config {
    pub issuer: String,
    pub scope: String,
    #[serde(alias = "authURL")]
    pub auth_url: String,
    #[serde(alias = "tokenURL")]
    pub token_url: String,
}

impl fmt::Display for Autoconfig {
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

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_label = match self.r#type {
            ServerType::Imap => "imap",
            ServerType::Pop3 => "pop3",
            ServerType::Smtp => "smtp",
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
                SecurityType::Plain => "Plain",
                SecurityType::Starttls => "STARTTLS",
                SecurityType::Tls => "SSL",
            };
            write!(f, " ({label})")?;
        }

        let mut first = true;
        for auth in &self.authentication {
            f.write_str(if first { " " } else { ", " })?;
            first = false;
            f.write_str(match auth {
                AuthenticationType::PasswordCleartext => "password-cleartext",
                AuthenticationType::PasswordEncrypted => "password-encrypted",
                AuthenticationType::Ntlm => "NTLM",
                AuthenticationType::GsApi => "GSAPI",
                AuthenticationType::ClientIPAddress => "client-IP-address",
                AuthenticationType::TlsClientCert => "TLS-client-cert",
                AuthenticationType::OAuth2 => "OAuth2",
                AuthenticationType::None => "none",
            })?;
        }

        Ok(())
    }
}

impl fmt::Display for Documentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.descriptions.first() {
            Some(Description {
                lang: Some(lang),
                text,
            }) => write!(f, "{} ({lang}: {text})", self.url),
            Some(Description { lang: None, text }) => write!(f, "{} {text}", self.url),
            None => write!(f, "{}", self.url),
        }
    }
}

impl fmt::Display for OAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  {:11}{}", "Issuer", self.issuer)?;
        writeln!(f, "  {:11}{}", "Scope", self.scope)?;
        writeln!(f, "  {:11}{}", "Auth URL", self.auth_url)?;
        write!(f, "  {:11}{}", "Token URL", self.token_url)
    }
}

// serde-xml-rs 0.8 wraps the text content of a leaf element in a
// `#text` field. Unit enums deserialized from `<el>VARIANT</el>` need
// a wrapper that unwraps that field before passing the variant name
// to serde. These helpers are deserialize-only so JSON serialization
// stays clean (`"socketType": "tls"` instead of `{"#text": "tls"}`).
mod text_enum {
    use serde::{Deserialize, Deserializer};

    #[derive(Deserialize)]
    struct Text<T> {
        #[serde(rename = "#text")]
        text: T,
    }

    pub mod option {
        use super::*;

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            Text::<T>::deserialize(deserializer).map(|t| Some(t.text))
        }
    }

    pub mod vec {
        use super::*;
        use alloc::vec::Vec;

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
    use super::*;

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
        let cfg: Autoconfig =
            serde_xml_rs::from_str(SAMPLE).expect("autoconfig XML should deserialize");

        assert_eq!(cfg.version, "1.1");

        let p = &cfg.email_provider;
        assert_eq!(p.id, "example.com");
        assert_eq!(p.domain, vec!["example.com", "example.org"]);
        assert_eq!(p.display_name.as_deref(), Some("Example Mail"));
        assert_eq!(p.display_short_name.as_deref(), Some("Example"));

        assert_eq!(p.incoming_server.len(), 2);

        let imap = &p.incoming_server[0];
        assert!(matches!(imap.r#type, ServerType::Imap));
        assert_eq!(imap.hostname.as_deref(), Some("imap.example.com"));
        assert_eq!(imap.port, Some(993));
        assert!(matches!(imap.socket_type, Some(SecurityType::Tls)));
        assert_eq!(imap.username.as_deref(), Some("%EMAILADDRESS%"));
        assert_eq!(imap.authentication.len(), 2);
        assert!(matches!(imap.authentication[0], AuthenticationType::OAuth2));
        assert!(matches!(
            imap.authentication[1],
            AuthenticationType::PasswordCleartext
        ));
        assert!(imap.pop3.is_none());

        let pop = &p.incoming_server[1];
        assert!(matches!(pop.r#type, ServerType::Pop3));
        assert!(matches!(pop.socket_type, Some(SecurityType::Tls)));
        assert!(matches!(
            pop.authentication[0],
            AuthenticationType::PasswordEncrypted
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
        assert!(matches!(smtp.r#type, ServerType::Smtp));
        assert!(matches!(smtp.socket_type, Some(SecurityType::Starttls)));

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

    // Minimal real-world shape: single IMAP + SMTP, no documentation,
    // no OAuth2. Catches regressions where optional sections silently
    // require defaulted structure.
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

        let cfg: Autoconfig = serde_xml_rs::from_str(xml).unwrap();
        assert!(cfg.oauth2.is_none());
        assert!(cfg.email_provider.documentation.is_empty());
        assert_eq!(cfg.email_provider.incoming_server.len(), 1);
        assert_eq!(cfg.email_provider.outgoing_server.len(), 1);
    }

    // Lowercase variant identifiers (no SSL/STARTTLS aliases) must
    // still work via `rename_all = "camelCase"`.
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

        let cfg: Autoconfig = serde_xml_rs::from_str(xml).unwrap();
        assert!(matches!(
            cfg.email_provider.incoming_server[0].socket_type,
            Some(SecurityType::Starttls)
        ));
        assert!(matches!(
            cfg.email_provider.outgoing_server[0].socket_type,
            Some(SecurityType::Plain)
        ));
        assert!(matches!(
            cfg.email_provider.incoming_server[0].authentication[0],
            AuthenticationType::None
        ));
    }
}
