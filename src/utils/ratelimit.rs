use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{interval, Duration};

pub struct RateLimiter {
    sem: Arc<Semaphore>,
    pps: u64,
    burst: u64,
}

impl RateLimiter {
    pub fn new(pps: u64, burst: u64) -> Arc<Self> {
        let burst = burst.max(1);
        let sem = Arc::new(Semaphore::new(burst as usize));
        let rl = Arc::new(Self { sem: sem.clone(), pps, burst });

        if pps > 0 {
            let rl_clone = rl.clone();
            tokio::spawn(async move {
                let mut tick = interval(Duration::from_millis(100)); // 10 ticks/sec
                let per_tick = ((pps + 9) / 10).max(1);
                loop {
                    tick.tick().await;
                    let available = rl_clone.sem.available_permits() as u64;
                    let capacity_left = rl_clone.burst.saturating_sub(available);
                    let to_add = per_tick.min(capacity_left) as usize;
                    if to_add > 0 {
                        rl_clone.sem.add_permits(to_add);
                    }
                }
            });
        } else {
            sem.add_permits((burst as usize).saturating_sub(sem.available_permits()));
        }

        rl
    }

    pub async fn acquire(&self) {
        if self.pps == 0 { return; }
        let _permit = self.sem.acquire().await.expect("rate limiter semaphore closed");
    }
}
