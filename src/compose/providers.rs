//! # Fixed provider rules
//!
//! Hard-coded configs for providers whose services cannot be (fully)
//! discovered: Google and Microsoft publish no autoconfig OAuth
//! endpoints nor PACC documents, and their custom-domain offerings
//! (Google Workspace, Microsoft 365) are only detectable through MX
//! records. These rules should shrink over time as providers adopt
//! discoverable mechanisms (PACC, RFC 8414 metadata).

use alloc::{format, string::ToString, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::compose::config::{
    DiscoveryAuthMethod, DiscoveryConfigSource, DiscoveryEndpoint, DiscoverySecurity,
    DiscoveryService, DiscoveryServiceConfig,
};

/// A provider covered by a fixed rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryKnownProvider {
    /// Google (Gmail, Google Workspace).
    Google,
    /// Microsoft (Outlook.com, Microsoft 365, Exchange Online).
    Microsoft,
}

impl DiscoveryKnownProvider {
    /// Matches a provider from an email domain.
    pub fn from_domain(domain: &str) -> Option<Self> {
        let google = ["gmail.com", "googlemail.com"];
        if google.iter().any(|d| domain.eq_ignore_ascii_case(d)) {
            return Some(Self::Google);
        }

        if domain.eq_ignore_ascii_case("msn.com") {
            return Some(Self::Microsoft);
        }

        // NOTE: Microsoft consumer domains come in country flavors
        // (outlook.com.br, hotmail.fr, live.de, ...); match on the
        // first label instead of maintaining the full list.
        let label = domain.split('.').next().unwrap_or(domain);
        let microsoft = ["outlook", "hotmail", "live"];
        if microsoft.iter().any(|l| label.eq_ignore_ascii_case(l)) {
            return Some(Self::Microsoft);
        }

        None
    }

    /// Matches a provider from an MX exchange host, catching custom
    /// domains hosted on Google Workspace or Microsoft 365.
    pub fn from_mx(exchange: &str) -> Option<Self> {
        let host = exchange.trim_end_matches('.').to_ascii_lowercase();

        let google = [".google.com", ".googlemail.com"];
        if google.iter().any(|s| host.ends_with(s)) {
            return Some(Self::Google);
        }

        if host.ends_with(".protection.outlook.com") {
            return Some(Self::Microsoft);
        }

        None
    }

    /// Returns the fixed configs for `email` on this provider.
    pub fn configs(self, email: &str) -> Vec<DiscoveryServiceConfig> {
        match self {
            Self::Google => google_configs(email),
            Self::Microsoft => microsoft_configs(email),
        }
    }
}

fn google_configs(email: &str) -> Vec<DiscoveryServiceConfig> {
    let source = DiscoveryConfigSource::Provider(DiscoveryKnownProvider::Google);

    // NOTE: no device authorization grant: Google's device flow
    // restricts scopes to an allowlist that excludes Gmail, Calendar
    // and Contacts. Password stands for an app password, which
    // requires 2-step verification on the account.
    let mail_auth = vec![
        DiscoveryAuthMethod::OauthAuthorizationCodeGrant {
            authorization_endpoint: GOOGLE_AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_string(),
            scope: Some("https://mail.google.com/".to_string()),
        },
        DiscoveryAuthMethod::Password,
    ];

    let dav_auth = |scope: &str| {
        vec![DiscoveryAuthMethod::OauthAuthorizationCodeGrant {
            authorization_endpoint: GOOGLE_AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_string(),
            scope: Some(scope.to_string()),
        }]
    };

    vec![
        DiscoveryServiceConfig {
            service: DiscoveryService::Imap,
            endpoint: DiscoveryEndpoint::Tcp {
                host: "imap.gmail.com".to_string(),
                port: 993,
                security: DiscoverySecurity::Tls,
            },
            username: Some(email.to_string()),
            auth: mail_auth.clone(),
            source,
        },
        DiscoveryServiceConfig {
            service: DiscoveryService::Pop3,
            endpoint: DiscoveryEndpoint::Tcp {
                host: "pop.gmail.com".to_string(),
                port: 995,
                security: DiscoverySecurity::Tls,
            },
            username: Some(email.to_string()),
            auth: mail_auth.clone(),
            source,
        },
        DiscoveryServiceConfig {
            service: DiscoveryService::Smtp,
            endpoint: DiscoveryEndpoint::Tcp {
                host: "smtp.gmail.com".to_string(),
                port: 465,
                security: DiscoverySecurity::Tls,
            },
            username: Some(email.to_string()),
            auth: mail_auth,
            source,
        },
        DiscoveryServiceConfig {
            service: DiscoveryService::Caldav,
            endpoint: DiscoveryEndpoint::Http(format!(
                "https://apidata.googleusercontent.com/caldav/v2/{email}/user"
            )),
            username: Some(email.to_string()),
            auth: dav_auth("https://www.googleapis.com/auth/calendar"),
            source,
        },
        DiscoveryServiceConfig {
            service: DiscoveryService::Carddav,
            endpoint: DiscoveryEndpoint::Http(format!(
                "https://www.googleapis.com/carddav/v1/principals/{email}/"
            )),
            username: Some(email.to_string()),
            auth: dav_auth("https://www.googleapis.com/auth/carddav"),
            source,
        },
    ]
}

fn microsoft_configs(email: &str) -> Vec<DiscoveryServiceConfig> {
    let source = DiscoveryConfigSource::Provider(DiscoveryKnownProvider::Microsoft);

    // NOTE: no password: Exchange Online retired basic
    // authentication. No CalDAV/CardDAV either: Exchange exposes
    // calendars and contacts over Graph/EWS only.
    let auth = |scope: &str| {
        let scope = Some(format!("{scope} offline_access"));

        vec![
            DiscoveryAuthMethod::OauthAuthorizationCodeGrant {
                authorization_endpoint: MICROSOFT_AUTHORIZATION_ENDPOINT.to_string(),
                token_endpoint: MICROSOFT_TOKEN_ENDPOINT.to_string(),
                scope: scope.clone(),
            },
            DiscoveryAuthMethod::OauthDeviceAuthorizationGrant {
                device_authorization_endpoint: MICROSOFT_DEVICE_AUTHORIZATION_ENDPOINT.to_string(),
                token_endpoint: MICROSOFT_TOKEN_ENDPOINT.to_string(),
                scope,
            },
        ]
    };

    vec![
        DiscoveryServiceConfig {
            service: DiscoveryService::Imap,
            endpoint: DiscoveryEndpoint::Tcp {
                host: "outlook.office365.com".to_string(),
                port: 993,
                security: DiscoverySecurity::Tls,
            },
            username: Some(email.to_string()),
            auth: auth("https://outlook.office365.com/IMAP.AccessAsUser.All"),
            source,
        },
        DiscoveryServiceConfig {
            service: DiscoveryService::Pop3,
            endpoint: DiscoveryEndpoint::Tcp {
                host: "outlook.office365.com".to_string(),
                port: 995,
                security: DiscoverySecurity::Tls,
            },
            username: Some(email.to_string()),
            auth: auth("https://outlook.office365.com/POP.AccessAsUser.All"),
            source,
        },
        DiscoveryServiceConfig {
            service: DiscoveryService::Smtp,
            endpoint: DiscoveryEndpoint::Tcp {
                host: "smtp.office365.com".to_string(),
                port: 587,
                security: DiscoverySecurity::Starttls,
            },
            username: Some(email.to_string()),
            auth: auth("https://outlook.office365.com/SMTP.Send"),
            source,
        },
    ]
}

const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

const MICROSOFT_AUTHORIZATION_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MICROSOFT_DEVICE_AUTHORIZATION_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode";
