
use rustlite_scan::utils::RateLimiter;

#[tokio::test]
async fn ratelimit_config_getters() {
    let rl = RateLimiter::new(123, 7);
    assert_eq!(rl.pps(), 123);
    assert_eq!(rl.burst(), 7);

    let rl2 = RateLimiter::new(0, 10);
    assert_eq!(rl2.pps(), 0);
    assert_eq!(rl2.burst(), 10);
}
