use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::{Duration, timeout}};

use crate::{probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}}, service::ServiceFingerprint};

pub struct ElasticProbe;

#[async_trait::async_trait]
impl Probe for ElasticProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let timeout_dur = Duration::from_millis(timeout_ms);

        let mut tcp = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "elastic", "connect_timeout");
                return Some(ServiceFingerprint::from_banner(ip, port, "elastic", evidence));
            }
        };

        // Minimal HTTP GET /
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: rustlite-scan\r\nConnection: close\r\n\r\n"
        );

        if timeout(timeout_dur, tcp.write_all(req.as_bytes())).await.is_err() {
            push_line(&mut evidence, "elastic", "write_error");
            return Some(ServiceFingerprint::from_banner(ip, port, "elastic", evidence));
        }

        let mut buf = vec![0u8; 16384];
        let n = match timeout(timeout_dur, tcp.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                push_line(&mut evidence, "elastic", "read_error");
                return Some(ServiceFingerprint::from_banner(ip, port, "elastic", evidence));
            }
        };

        let resp = String::from_utf8_lossy(&buf[..n]);

        // Find JSON body (after \r\n\r\n)
        if let Some(idx) = resp.find("\r\n\r\n") {
            let body = &resp[idx + 4..];

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                // Elasticsearch or OpenSearch?
                if json.get("version").is_some() {
                    if let Some(v) = json["version"]["number"].as_str() {
                        push_line(&mut evidence, "elastic_version", v);
                    }
                    if let Some(f) = json["version"]["build_flavor"].as_str() {
                        push_line(&mut evidence, "elastic_build_flavor", f);
                    }
                    if let Some(l) = json["version"]["lucene_version"].as_str() {
                        push_line(&mut evidence, "elastic_lucene_version", l);
                    }
                }

                if let Some(dist) = json["version"]["distribution"].as_str() {
                    push_line(&mut evidence, "elastic_distribution", dist);
                }

                if let Some(name) = json["name"].as_str() {
                    push_line(&mut evidence, "elastic_node_name", name);
                }
                if let Some(cname) = json["cluster_name"].as_str() {
                    push_line(&mut evidence, "elastic_cluster_name", cname);
                }
                if let Some(uuid) = json["cluster_uuid"].as_str() {
                    push_line(&mut evidence, "elastic_cluster_uuid", uuid);
                }
            } else {
                push_line(&mut evidence, "elastic", "invalid_json");
            }
        } else {
            push_line(&mut evidence, "elastic", "no_json_body");
        }

        Some(ServiceFingerprint::from_banner(ip, port, "elastic", evidence))
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        self.probe(ip, port, ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000)).await
    }

    fn ports(&self) -> Vec<u16> { vec![9200] }
    fn name(&self) -> &'static str { "elastic" }
}
