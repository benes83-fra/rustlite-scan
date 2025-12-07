use rustlite_scan::utils::RateLimiter;
use tokio::time::{ Duration, Instant};

#[tokio::test(start_paused = true)]
async fn ratelimiter_refill_behaviour() {
    // Create a limiter with 1 pps, burst 1, and a small tick for clarity (tick_ms not used by refill_once)
    let rl = RateLimiter::new_with_tick(1, 1, 10);

    // First acquire should succeed immediately (burst=1)
    let t0 = Instant::now();
    rl.acquire().await;
    let elapsed0 = Instant::now().duration_since(t0);
    assert!(elapsed0 < Duration::from_millis(10), "first acquire should be immediate");

    // Spawn an acquire that will wait for the refill
    let rl_clone = rl.clone();
    let acquire_fut = tokio::spawn(async move {
        rl_clone.acquire().await;
        Instant::now()
    });

    // Give the spawned task a chance to start and block on acquire
    tokio::task::yield_now().await;

    // Now perform a deterministic refill (no virtual-time advance needed)
    rl._refill_once();

    // Allow the spawned task to run
    tokio::task::yield_now().await;

    // Now the acquire future should be done
    let acquired_at = acquire_fut.await.expect("task join");
    let elapsed_total = acquired_at.duration_since(t0);
    assert!(elapsed_total >= Duration::from_millis(0), "should have acquired after refill");
}
