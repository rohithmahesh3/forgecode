use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{DateTime, Utc};
use derive_setters::Setters;
use serde::{Deserialize, Serialize};

use crate::{AccessToken, ApiKey, OAuthConfig, ProviderId, RefreshToken, URLParam, URLParamValue};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Setters)]
pub struct AuthCredential {
    pub id: ProviderId,
    pub auth_details: AuthDetails,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub url_params: HashMap<URLParam, URLParamValue>,
}
impl AuthCredential {
    pub fn new_api_key(id: ProviderId, api_key: ApiKey) -> Self {
        Self {
            id,
            auth_details: AuthDetails::ApiKey(api_key),
            url_params: HashMap::new(),
        }
    }
    pub fn new_oauth(id: ProviderId, tokens: OAuthTokens, config: OAuthConfig) -> Self {
        Self {
            id,
            auth_details: AuthDetails::OAuth { tokens, config },
            url_params: HashMap::new(),
        }
    }
    pub fn new_oauth_with_api_key(
        id: ProviderId,
        tokens: OAuthTokens,
        api_key: ApiKey,
        config: OAuthConfig,
    ) -> Self {
        Self {
            id,
            auth_details: AuthDetails::OAuthWithApiKey { tokens, api_key, config },
            url_params: HashMap::new(),
        }
    }

    pub fn new_google_adc(id: ProviderId, access_token: ApiKey) -> Self {
        Self {
            id,
            auth_details: AuthDetails::GoogleAdc(access_token),
            url_params: HashMap::new(),
        }
    }

    /// Checks if the credential needs to be refreshed.
    pub fn needs_refresh(&self, buffer: chrono::Duration) -> bool {
        match &self.auth_details {
            AuthDetails::ApiKey(_) | AuthDetails::ApiKeys(_) => false,
            // Google ADC tokens are short-lived (1 hour) and should always be checked/refreshed
            AuthDetails::GoogleAdc(_) => true,
            AuthDetails::OAuth { tokens, .. } | AuthDetails::OAuthWithApiKey { tokens, .. } => {
                tokens.needs_refresh(buffer)
            }
        }
    }

    /// Gets the OAuth config if this credential is OAuth-based
    pub fn oauth_config(&self) -> Option<&OAuthConfig> {
        match &self.auth_details {
            AuthDetails::OAuth { config, .. } | AuthDetails::OAuthWithApiKey { config, .. } => {
                Some(config)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDetails {
    #[serde(alias = "ApiKey")]
    ApiKey(ApiKey),
    #[serde(alias = "ApiKeys")]
    ApiKeys(Vec<ApiKey>),
    #[serde(alias = "GoogleAdc")]
    GoogleAdc(ApiKey),
    #[serde(alias = "OAuth")]
    OAuth {
        tokens: OAuthTokens,
        config: OAuthConfig,
    },
    #[serde(alias = "OAuthWithApiKey")]
    OAuthWithApiKey {
        tokens: OAuthTokens,
        api_key: ApiKey,
        config: OAuthConfig,
    },
}

/// Global counter for round-robin key selection across `ApiKeys` variants.
static ROUND_ROBIN_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl AuthDetails {
    /// Returns the bearer token string for any auth variant.
    /// For `ApiKeys`, cycles through keys using atomic round-robin.
    pub fn bearer_token(&self) -> Option<&str> {
        match self {
            AuthDetails::ApiKey(key) => Some(key.as_str()),
            AuthDetails::ApiKeys(keys) => {
                if keys.is_empty() {
                    return None;
                }
                let idx = ROUND_ROBIN_COUNTER.fetch_add(1, Ordering::Relaxed) % keys.len();
                Some(keys[idx].as_str())
            }
            AuthDetails::GoogleAdc(key) => Some(key.as_str()),
            AuthDetails::OAuth { tokens, .. } => Some(tokens.access_token.as_str()),
            AuthDetails::OAuthWithApiKey { api_key, .. } => Some(api_key.as_str()),
        }
    }

    pub fn api_key(&self) -> Option<&ApiKey> {
        match self {
            AuthDetails::ApiKey(api_key) => Some(api_key),
            AuthDetails::ApiKeys(keys) => keys.first(),
            AuthDetails::GoogleAdc(api_key) => Some(api_key),
            AuthDetails::OAuth { .. } => None,
            AuthDetails::OAuthWithApiKey { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub expires_at: DateTime<Utc>,
}

impl OAuthTokens {
    pub fn new(
        access_token: impl ToString,
        refresh_token: Option<impl ToString>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            access_token: access_token.to_string().into(),
            refresh_token: refresh_token.map(|a| a.to_string().into()),
            expires_at,
        }
    }

    /// Checks if the token is expired or will expire within the given buffer
    /// duration
    pub fn needs_refresh(&self, buffer: chrono::Duration) -> bool {
        let now = Utc::now();
        now + buffer >= self.expires_at
    }

    /// Checks if the token is currently expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}
