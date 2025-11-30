use rustlite_scan::probes;
use rustlite_scan::probes::Probe;
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::task;
    use hyper::{Body, Response, Server, Request, service::{make_service_fn, service_fn}};

    #[tokio::test]
    async fn http_probe_returns_server_header() {
        // start a tiny server that returns Server header
        let make_svc = make_service_fn(|_conn| async {
            Ok::<_, hyper::Error>(service_fn(|_req: Request<Body>| async {
                let mut resp = Response::new(Body::from("ok"));
                resp.headers_mut().insert("server", "test-server/1.2".parse().unwrap());
                Ok::<_, hyper::Error>(resp)
            }))
        });

        let addr = ([127,0,0,1], 0).into();
        let server = Server::try_bind(&addr).unwrap();
        let local_addr = server.local_addr();
        let srv = server.serve(make_svc);
        let _handle = task::spawn(srv);

        // run probe
        let probe = crate::probes::http::HttpProbe {};
        let fp = probe.probe(&local_addr.ip().to_string(), local_addr.port(), 1000).await;
        assert!(fp.is_some());
        let fp = fp.unwrap();
        assert!(fp.service.is_some() || fp.evidence.is_some());
    }
}

