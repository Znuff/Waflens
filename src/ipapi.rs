use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpApiResponse {
    #[serde(default)]
    pub query: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub continent: Option<String>,
    #[serde(rename = "continentCode")]
    #[serde(default)]
    pub continent_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(rename = "countryCode")]
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(rename = "regionName")]
    #[serde(default)]
    pub region_name: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub district: Option<String>,
    #[serde(default)]
    pub zip: Option<String>,
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub lon: Option<f64>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub offset: Option<i32>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub isp: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(rename = "as")]
    #[serde(default)]
    pub as_info: Option<String>,
    #[serde(default)]
    pub asname: Option<String>,
    #[serde(default)]
    pub mobile: Option<bool>,
    #[serde(default)]
    pub proxy: Option<bool>,
    #[serde(default)]
    pub hosting: Option<bool>,
}

pub struct IpApiCache {
    cache: Mutex<HashMap<String, String>>,
}

impl IpApiCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get the /24 subnet for an IP address
    fn get_subnet_24(ip: &str) -> Option<String> {
        // Try to parse as IP address
        if let Ok(addr) = ip.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    Some(format!("{}.{}.{}.0", octets[0], octets[1], octets[2]))
                }
                IpAddr::V6(_) => {
                    // For IPv6, just use the full address (no /24 subnet concept)
                    Some(ip.to_string())
                }
            }
        } else {
            None
        }
    }

    /// Fetch IP information from ip-api.com, using /24 subnet caching
    pub fn get_ip_info(&self, ip: &str) -> Result<String> {
        // Get the /24 subnet to use as cache key
        let cache_key = Self::get_subnet_24(ip)
            .unwrap_or_else(|| ip.to_string());

        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // Not in cache - fetch from API
        let url = format!(
            "http://ip-api.com/json/{}?fields=query,status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting",
            cache_key
        );

        let response = reqwest::blocking::get(&url)?;
        let api_response: IpApiResponse = response.json()?;

        // Pretty-print the JSON response
        let pretty_json = serde_json::to_string_pretty(&api_response)?;

        // Cache the result
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(cache_key, pretty_json.clone());
        }

        Ok(pretty_json)
    }
}
