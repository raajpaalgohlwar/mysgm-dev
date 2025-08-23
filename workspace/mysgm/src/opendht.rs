use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::blocking::Client as ReqwestClient;
use serde_json::{from_str as json_decode, to_string as json_encode};

pub struct OpenDhtRestAdapter {
    proxy_address: String,
    proxy_port: u16,
}

impl OpenDhtRestAdapter {
    pub fn new(proxy_address: &str, proxy_port: u16) -> Self {
        Self {
            proxy_address: proxy_address.into(),
            proxy_port,
        }
    }
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn core::error::Error>> {
        // Implementation for getting a value from OpenDHT via REST API using reqwest
        let request_url = format!(
            "http://{}:{}/key/{}",
            self.proxy_address, self.proxy_port, key
        );
        let response = ReqwestClient::new()
            .get(&request_url)
            .send()
            .map_err(Box::new)?
            .error_for_status()
            .map_err(Box::new)?;
        let response_body = response.text()?;
        if response_body.is_empty() {
            Ok(None)
        } else {
            let json_value: serde_json::Value = json_decode(&response_body).map_err(Box::new)?;
            let data = STANDARD
                .decode(json_value["data"].as_str().unwrap_or_default())
                .map_err(Box::new)?;
            Ok(Some(data))
        }
    }
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn core::error::Error>> {
        // Implementation for putting a value into OpenDHT via REST API using reqwest
        let request_url = format!(
            "http://{}:{}/key/{}",
            self.proxy_address, self.proxy_port, key
        );
        let request_payload = serde_json::to_string(&serde_json::json!({
            "data": STANDARD.encode(value),
            "permanent": "true"
        }))
        .unwrap();
        let _response = ReqwestClient::new()
            .post(&request_url)
            .body(request_payload)
            .send()
            .map_err(Box::new)?
            .error_for_status()
            .map_err(Box::new)?;
        Ok(())
    }
    pub fn put_checked(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn core::error::Error>> {
        if let Ok(Some(_)) = self.get(key) {
            Err("Key already exists".into())
        } else {
            self.put(key, value)
        }
    }
}
