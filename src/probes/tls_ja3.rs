use openssl::ssl::SslRef;
use openssl::nid::Nid;
use md5::{Md5, Digest};

pub fn build_tls_server_fingerprint(ssl: &SslRef) -> (String, String) {
    // TLS version string (e.g. "TLSv1.3")
    let version = ssl.version_str().to_string();

    // Cipher name (e.g. "TLS_AES_256_GCM_SHA384")
    let cipher = ssl
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // ALPN (e.g. "h2", "http/1.1")
    let alpn = ssl
        .selected_alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_else(|| "".to_string());

    // Issuer CN (rough stack hint)
    let issuer_cn = ssl
        .peer_certificate()
        .and_then(|c| {
            c.issuer_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        })
        .unwrap_or_else(|| "".to_string());

    // Canonical fingerprint string
    let fp_str = format!(
        "ver={};cipher={};alpn={};issuer_cn={}",
        version, cipher, alpn, issuer_cn
    );

    // MD5 hash → JA3S-like
    let mut hasher = Md5::new();
    hasher.update(fp_str.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    (fp_str, hash)
}
