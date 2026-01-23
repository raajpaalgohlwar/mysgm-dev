use base64::{Engine, engine::general_purpose::STANDARD};
use core::error::Error;
use reqwest::blocking::Client as ReqwestClient;
use serde_json::{Value, from_str as json_decode, json, to_string as json_encode};

#[derive(Clone, Debug)]
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
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
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
            let json_value: Value = json_decode(&response_body).map_err(Box::new)?;
            let data_str = match &json_value {
                Value::Array(values) => values
                    .iter()
                    .find_map(|value| value.get("data").and_then(|data| data.as_str())),
                Value::Object(_) => json_value.get("data").and_then(|data| data.as_str()),
                _ => None,
            };
            match data_str {
                Some(data) if !data.is_empty() => {
                    Ok(Some(STANDARD.decode(data).map_err(Box::new)?))
                }
                _ => Ok(None),
            }
        }
    }
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        // Implementation for putting a value into OpenDHT via REST API using reqwest
        let request_url = format!(
            "http://{}:{}/key/{}",
            self.proxy_address, self.proxy_port, key
        );
        let request_payload = json_encode(&json!({
            "data": STANDARD.encode(value),
            "permanent": true
        }))
        .unwrap();
        let _response = ReqwestClient::new()
            .post(&request_url)
            .header("Content-Type", "application/json")
            .body(request_payload)
            .send()
            .map_err(Box::new)?
            .error_for_status()
            .map_err(Box::new)?;
        Ok(())
    }
    pub fn put_checked(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        if let Ok(Some(_)) = self.get(key) {
            Err("Key already exists".into())
        } else {
            match self.put(key, value) {
                Ok(()) => Ok(()),
                Err(err) => {
                    if let Ok(Some(_)) = self.get(key) {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }
}
