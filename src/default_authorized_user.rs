use std::path::Path;
use std::sync::RwLock;

use async_trait::async_trait;
use reqwest::{Client, Request};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::Token;

#[derive(Debug)]
pub(crate) struct DefaultAuthorizedUser {
    token: RwLock<Token>,
}

impl DefaultAuthorizedUser {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "https://accounts.google.com/o/oauth2/token";
    const USER_CREDENTIALS_PATH: &'static str =
        ".config/gcloud/application_default_credentials.json";

    pub(crate) async fn new(client: &HyperClient) -> Result<Self, Error> {
        let token = RwLock::new(Self::get_token(client).await?);
        Ok(Self { token })
    }

    async fn get_token(client: &Client) -> Result<Token, Error> {
        log::debug!("Loading user credentials file");
        let mut home = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(Self::USER_CREDENTIALS_PATH);
        let cred = UserCredentials::from_file(home.display().to_string()).await?;
        let token = client
            .post(Self::DEFAULT_TOKEN_GCP_URI)
            .header("content-type", "application/json")
            .json(&RefreshRequest {
                client_id: cred.client_id,
                client_secret: cred.client_secret,
                grant_type: "refresh_token".to_string(),
                refresh_token: cred.refresh_token,
            })
            .send()
            .await
            .map_err(Error::OAuthConnectionError)?
            .error_for_status()
            .map_err(|err| Error::ServerUnavailable(err.to_string()))?
            .json()
            .await?;
        Ok(token)
    }
}

#[async_trait]
impl ServiceAccount for DefaultAuthorizedUser {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        Err(Error::NoProjectId)
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        Some(self.token.read().unwrap().clone())
    }

    async fn refresh_token(&self, client: &Client, _scopes: &[&str]) -> Result<Token, Error> {
        let token = Self::get_token(client).await?;
        *self.token.write().unwrap() = token.clone();
        Ok(token)
    }
}

#[derive(Serialize, Debug)]
struct RefreshRequest {
    client_id: String,
    client_secret: String,
    grant_type: String,
    refresh_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserCredentials {
    /// Client id
    pub(crate) client_id: String,
    /// Client secret
    pub(crate) client_secret: String,
    /// Refresh Token
    pub(crate) refresh_token: String,
    /// Type
    pub(crate) r#type: String,
}

impl UserCredentials {
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<UserCredentials, Error> {
        let content = fs::read_to_string(path)
            .await
            .map_err(Error::UserProfilePath)?;
        Ok(serde_json::from_str(&content).map_err(Error::UserProfileFormat)?)
    }
}
