use base64::{Engine, engine::general_purpose::STANDARD};
use core::error::Error;

use crate::metrics::{MetricsEvent, log_event, now_ms};
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
        let started = now_ms();
        let response = ReqwestClient::new().get(&request_url).send().map_err(Box::new)?;
        let status = response.status();
        let response_body = response.text()?;
        let mut event = MetricsEvent::new("dht_get", started, now_ms());
        event.dht_key = Some(key.to_string());
        event.http_status = Some(status.as_u16());
        event.payload_bytes = Some(response_body.len());
        if !status.is_success() {
            event.result = "error".to_string();
            event.error = Some(format!("HTTP status {status}"));
        }
        log_event(&event);
        if !status.is_success() {
            return Err(format!("HTTP status {status}").into());
        }
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
        let started = now_ms();
        let response = ReqwestClient::new()
            .post(&request_url)
            .header("Content-Type", "application/json")
            .body(request_payload)
            .send()
            .map_err(Box::new)?;
        let status = response.status();
        let mut event = MetricsEvent::new("dht_put", started, now_ms());
        event.dht_key = Some(key.to_string());
        event.http_status = Some(status.as_u16());
        event.payload_bytes = Some(value.len());
        if !status.is_success() {
            event.result = "error".to_string();
            event.error = Some(format!("HTTP status {status}"));
        }
        log_event(&event);
        if !status.is_success() {
            return Err(format!("HTTP status {status}").into());
        }
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
