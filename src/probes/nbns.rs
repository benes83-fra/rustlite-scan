
use crate::probes::nbns_helper;
use crate::probes::helper::push_line;
use super::Probe;
use crate::service::ServiceFingerprint;
pub struct NbnsProbe;

#[async_trait::async_trait]
impl Probe for NbnsProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence=String::new();
        match nbns_helper::nbns_query(ip, timeout_ms).await {
                            Ok(res) => {
                                if res.names.is_empty() && res.unit_id.is_none() {
                                    eprintln! ("No name found so no response");
                                    push_line(&mut evidence, "NBNS", "no_response");
                                } else {
                                    for (i, n) in res.names.iter().enumerate() {
                                        eprintln!("Found some stuff!!!");
                                        push_line(&mut evidence, &format!("NBNS_name_{}", i), &format!("{} (type=0x{:02x}, flags=0x{:04x})", n.name, n.name_type, n.flags));
                                    }
                                    if let Some(mac) = res.unit_id {
                                        eprintln!("We got some macs!");
                                        push_line(&mut evidence, "NBNS_unit_id", &format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]));
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("We made a mistake {}", e);
                                push_line(&mut evidence, "NBNS", &format!("error: {}", e));
                            }
                            }

                            return Some(ServiceFingerprint::from_banner(ip, port, "smb", evidence));

    }


    fn ports(&self) -> Vec<u16> { vec![137] }
    fn name(&self) -> &'static str { "nbns" }

}