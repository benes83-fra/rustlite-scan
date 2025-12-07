use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{ Duration};

pub struct RateLimiter {
    sem: Arc<Semaphore>,
    pps: u64,
    burst: u64,
    tick_ms: u64,
}

impl RateLimiter {
    /// Create a limiter with the default tick interval (100 ms)
    pub fn new(pps: u64, burst: u64) -> Arc<Self> {
        Self::new_with_tick(pps, burst, 100)
    }

    /// Create a limiter with an injectable tick interval (milliseconds).
    /// Tests can use a small tick_ms to make deterministic virtual-time tests.
    pub fn new_with_tick(pps: u64, burst: u64, tick_ms: u64) -> Arc<Self> {
        let burst = burst.max(1);
        let sem = Arc::new(Semaphore::new(burst as usize));
        let rl = Arc::new(Self { sem: sem.clone(), pps, burst, tick_ms: tick_ms.max(1) });

        if pps > 0 {
            let rl_clone = rl.clone();
            tokio::spawn(async move {
                // Use a simple sleep-based loop so virtual-time tests can advance exactly tick_ms
                let tick_dur = Duration::from_millis(rl_clone.tick_ms);
                // compute per-tick refill: distribute pps across 1000/tick_ms ticks per second
                let ticks_per_sec = 1000u64 / rl_clone.tick_ms;
                let per_tick = ((rl_clone.pps + ticks_per_sec - 1) / ticks_per_sec).max(1);

                loop {
                    tokio::time::sleep(tick_dur).await;
                    let available = rl_clone.sem.available_permits() as u64;
                    let capacity_left = rl_clone.burst.saturating_sub(available);
                    let to_add = per_tick.min(capacity_left) as usize;
                    if to_add > 0 {
                        rl_clone.sem.add_permits(to_add);
                    }
                }
            });
        }
         else {
            // If pps == 0, ensure burst permits are available
            sem.add_permits((burst as usize).saturating_sub(sem.available_permits()));
        }

        rl
    }

    /// Acquire a permit (awaits if none available). If pps == 0 this is a no-op.
    pub async fn acquire(&self) {
        if self.pps == 0 { return; }
        let _permit = self.sem.acquire().await.expect("rate limiter semaphore closed");
    }

    /// Packets-per-second configured for this limiter
    pub fn pps(&self) -> u64 {
        self.pps
    }

    /// Burst capacity configured for this limiter
    pub fn burst(&self) -> u64 {
        self.burst
    }
   
    /// Perform a single refill step (useful for deterministic tests).
    /// This adds the same number of permits that the background task would add for one tick.
    pub fn _refill_once(&self) {
        // compute ticks per second and per-tick refill consistent with new_with_tick
        let ticks_per_sec = 1000u64 / self.tick_ms.max(1);
        let per_tick = ((self.pps + ticks_per_sec - 1) / ticks_per_sec).max(1);

        let available = self.sem.available_permits() as u64;
        let capacity_left = self.burst.saturating_sub(available);
        let to_add = per_tick.min(capacity_left) as usize;
        if to_add > 0 {
            self.sem.add_permits(to_add);
        }
}

}


