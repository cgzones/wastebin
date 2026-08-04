use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Semaphore;

use crate::errors::Error;

/// Sets a flag once the request that owns it goes away.
///
/// The guard lives in the future that awaits the work, so a request dropped by the timeout layer
/// or by a disconnecting client drops the guard and marks the work abandoned.
struct AbandonGuard(Arc<AtomicBool>);

impl Drop for AbandonGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Runs the CPU-bound parts of a request — syntax highlighting and Markdown rendering — with a
/// bound on how many may run at once.
///
/// Both are handed to [`tokio::task::spawn_blocking`], which cannot be cancelled: the request
/// timeout stops waiting for the answer but the thread keeps going. Without a bound, requests
/// arriving faster than they complete pile onto the blocking pool, and every abandoned one still
/// costs a full render. Waiting for a permit before spawning keeps that queue in the runtime,
/// where an abandoned request drops out of it instead of occupying a thread.
#[derive(Clone)]
pub(crate) struct Renderer {
    permits: Arc<Semaphore>,
}

impl Renderer {
    /// Allow `limit` renders to run concurrently.
    pub(crate) fn new(limit: NonZeroUsize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit.get())),
        }
    }

    /// Bound concurrency to the machine's parallelism, which is what the work is limited by.
    pub(crate) fn with_available_parallelism() -> Self {
        let limit = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
        Self::new(limit)
    }

    /// Run `job` on a blocking thread once a permit is free.
    ///
    /// If the caller goes away while queueing, `job` is never started.
    pub(crate) async fn run<T, F>(&self, job: F) -> Result<T, Error>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| Error::RendererGone)?;

        let abandoned = Arc::new(AtomicBool::new(false));
        // Dropped together with this future, which is how the closure learns the caller is gone.
        let _guard = AbandonGuard(Arc::clone(&abandoned));

        let handle = tokio::task::spawn_blocking(move || {
            // Held for the duration so a queued render waits for a running one to finish.
            let _permit = permit;

            if abandoned.load(Ordering::Relaxed) {
                return None;
            }

            Some(job())
        });

        handle.await?.ok_or(Error::Abandoned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn runs_at_most_the_permitted_number_concurrently() {
        let renderer = Renderer::new(NonZeroUsize::new(2).unwrap());
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let jobs = (0..16)
            .map(|_| {
                let renderer = renderer.clone();
                let running = Arc::clone(&running);
                let peak = Arc::clone(&peak);

                tokio::spawn(async move {
                    renderer
                        .run(move || {
                            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(20));
                            running.fetch_sub(1, Ordering::SeqCst);
                        })
                        .await
                })
            })
            .collect::<Vec<_>>();

        for job in jobs {
            job.await.unwrap().unwrap();
        }

        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "ran {} at once",
            peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn skips_work_whose_caller_went_away() {
        // One permit, held by a job that runs long enough for the queued ones to be dropped.
        let renderer = Renderer::new(NonZeroUsize::new(1).unwrap());
        let started = Arc::new(AtomicUsize::new(0));

        let blocker = {
            let renderer = renderer.clone();
            tokio::spawn(async move {
                renderer
                    .run(|| std::thread::sleep(Duration::from_millis(300)))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        let queued = (0..8)
            .map(|_| {
                let renderer = renderer.clone();
                let started = Arc::clone(&started);
                tokio::spawn(async move {
                    renderer
                        .run(move || {
                            started.fetch_add(1, Ordering::SeqCst);
                        })
                        .await
                })
            })
            .collect::<Vec<_>>();

        // Give them time to queue on the semaphore, then abandon them.
        tokio::time::sleep(Duration::from_millis(50)).await;
        for job in &queued {
            job.abort();
        }

        blocker.await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            started.load(Ordering::SeqCst),
            0,
            "abandoned work was still executed"
        );
    }
}
