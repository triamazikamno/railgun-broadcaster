use super::error::DnsResolveError;
use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::TXT;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Clone)]
pub(super) struct TxtResolver {
    doh_endpoint: String,
    http: Client,
    system: Option<hickory_resolver::TokioResolver>,
    cache: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl TxtResolver {
    pub(super) fn new(
        doh_endpoint: String,
        http: Option<Client>,
        allow_system_dns: bool,
    ) -> Result<Self, DnsResolveError> {
        let http = match http {
            Some(http) => http,
            None => Client::builder()
                .user_agent("waku-rust")
                .build()
                .map_err(DnsResolveError::HttpClient)?,
        };

        let system = if allow_system_dns {
            Some(hickory_resolver::TokioResolver::builder_tokio()?.build())
        } else {
            None
        };

        Ok(Self {
            doh_endpoint,
            http,
            system,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub(super) async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, DnsResolveError> {
        if let Some(cached) = self.cache.lock().await.get(domain).cloned() {
            return Ok(cached);
        }

        let res = match self.resolve_txt_doh(domain).await {
            Ok(v) if !v.is_empty() => v,
            Ok(_) | Err(_) if self.system.is_some() => self.resolve_txt_system(domain).await?,
            Ok(v) => v,
            Err(error) => return Err(error),
        };

        self.cache
            .lock()
            .await
            .insert(domain.to_string(), res.clone());

        Ok(res)
    }

    async fn resolve_txt_system(&self, domain: &str) -> Result<Vec<String>, DnsResolveError> {
        let Some(system) = self.system.as_ref() else {
            return Ok(Vec::new());
        };
        let response =
            system
                .txt_lookup(domain)
                .await
                .map_err(|source| DnsResolveError::SystemLookup {
                    domain: domain.to_string(),
                    source,
                })?;

        Ok(response
            .iter()
            .flat_map(hickory_resolver::proto::rr::rdata::TXT::txt_data)
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect())
    }

    async fn resolve_txt_doh(&self, domain: &str) -> Result<Vec<String>, DnsResolveError> {
        let request = build_txt_query(domain)?;

        let resp = self
            .http
            .post(&self.doh_endpoint)
            .header(reqwest::header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, DNS_MESSAGE_CONTENT_TYPE)
            .body(request)
            .send()
            .await
            .map_err(DnsResolveError::DohRequest)?;

        let status = resp.status();
        if !status.is_success() {
            return Err(DnsResolveError::DohStatus(status));
        }

        let body = resp.bytes().await.map_err(DnsResolveError::DohBody)?;
        let parsed = Message::from_vec(&body).map_err(DnsResolveError::DohParse)?;
        if parsed.response_code() != ResponseCode::NoError {
            return Err(DnsResolveError::DohResponseCode(parsed.response_code()));
        }

        Ok(parsed
            .answers()
            .iter()
            .filter_map(|record| match record.data() {
                RData::TXT(txt) => Some(txt_to_string(txt)),
                _ => None,
            })
            .collect())
    }
}

fn build_txt_query(domain: &str) -> Result<Vec<u8>, DnsResolveError> {
    let mut name = Name::from_ascii(domain).map_err(DnsResolveError::DohEncode)?;
    name.set_fqdn(true);
    let mut message = Message::new();
    message
        .set_recursion_desired(true)
        .add_query(Query::query(name, RecordType::TXT));
    message.to_vec().map_err(DnsResolveError::DohEncode)
}

fn txt_to_string(txt: &TXT) -> String {
    let mut value = String::new();
    for part in txt.txt_data() {
        value.push_str(&String::from_utf8_lossy(part));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::MessageType;
    use hickory_resolver::proto::rr::Record;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn spawn_doh_response(status_line: &'static str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock DoH server");
        let addr = listener.local_addr().expect("mock DoH addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let header = format!(
                    "HTTP/1.1 {status_line}\r\ncontent-type: {DNS_MESSAGE_CONTENT_TYPE}\r\ncontent-length: {}\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(header.as_bytes())
                    .expect("write mock DoH response header");
                stream
                    .write_all(&body)
                    .expect("write mock DoH response body");
            }
        });
        format!("http://{addr}/dns-query")
    }

    fn txt_response_body(domain: &str, txt_chunks: Vec<String>) -> Vec<u8> {
        let mut name = Name::from_ascii(domain).expect("test DNS name");
        name.set_fqdn(true);
        let mut message = Message::new();
        message
            .set_message_type(MessageType::Response)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .add_query(Query::query(name.clone(), RecordType::TXT))
            .add_answer(Record::from_rdata(
                name,
                60,
                RData::TXT(TXT::new(txt_chunks)),
            ));
        message.to_vec().expect("encode mock DoH response")
    }

    #[test]
    fn no_system_dns_skips_system_resolver_initialization() {
        let resolver = TxtResolver::new("http://127.0.0.1:9/dns-query".to_string(), None, false)
            .expect("resolver");
        assert!(resolver.system.is_none());
    }

    #[tokio::test]
    async fn doh_wireformat_txt_response_is_parsed() {
        let endpoint = spawn_doh_response(
            "200 OK",
            txt_response_body(
                "example.invalid",
                vec!["part1".to_string(), "part2".to_string()],
            ),
        );
        let resolver = TxtResolver::new(endpoint, None, false).expect("resolver");
        let records = resolver
            .resolve_txt("example.invalid")
            .await
            .expect("DoH TXT lookup");
        assert_eq!(records, vec!["part1part2"]);
    }

    #[tokio::test]
    async fn no_system_dns_reports_doh_failure() {
        let endpoint = spawn_doh_response("503 Service Unavailable", Vec::new());
        let resolver = TxtResolver::new(endpoint, None, false).expect("resolver");
        let err = resolver
            .resolve_txt("example.invalid")
            .await
            .expect_err("DoH failure should not fall back to system DNS");
        assert!(matches!(err, DnsResolveError::DohStatus(_)));
    }
}
