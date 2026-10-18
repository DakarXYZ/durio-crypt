//! Chaos actions on the stack, asked of `scripts/testkit-backend.sh chaos`
//! through files in `STOAT_CHAOS_DIR` (the test container has no Docker):
//! the test writes `<n>.req` = `"<action> <target>"`, the script runs
//! `docker <action> durio-test-<target>` and renames it to `<n>.done`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// `None` unless the chaos runner is on the other side
pub fn dir() -> Option<std::path::PathBuf> {
    std::env::var("STOAT_CHAOS_DIR").ok().map(Into::into)
}

/// Ask for `docker <action> durio-test-<target>` (`restart`, `stop`,
/// `start`; `redis`, `rabbit`, `delta`, `bonfire`, `autumn`, `pushd`) and
/// wait until it is done (for `start`/`restart` of delta: until it answers)
pub async fn act(action: &str, target: &str) -> Duration {
    let dir = dir().expect("STOAT_CHAOS_DIR");
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let tag = format!("{}-{n:03}", std::process::id());
    let req = dir.join(format!("{tag}.req"));
    let done = dir.join(format!("{tag}.done"));
    let tmp = dir.join(format!("{tag}.tmp"));
    std::fs::write(&tmp, format!("{action} {target}\n")).expect("write chaos request");
    std::fs::rename(&tmp, &req).expect("publish chaos request");
    let started = Instant::now();
    while !done.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(180),
            "chaos runner did not do `{action} {target}`"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    started.elapsed()
}
