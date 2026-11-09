//! Runs selected test files with an arbitrary `node`-compatible executable.
//!
//! The executable is passed in rather than hard-coded so the same harness can
//! measure rustnode and, for comparison, a real Node binary.
//!
//! Each file runs in its own process with a wall-clock limit, because the whole
//! point is to survive a runtime that cannot start Node's test harness at all.
//! Tests from parallel-safe suites run several at a time; `sequential` runs alone,
//! matching Node's own split.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::result::{suite_of, FileResult};
use crate::select::{TestFile, PARALLEL_SAFE_SUITES};

/// Bytes of stderr kept per test, enough to show the first failing assertion.
const STDERR_HEAD_BYTES: usize = 4096;
/// Bytes of stdout kept per test; Node's reporters write summaries there.
const STDOUT_HEAD_BYTES: usize = 2048;
/// How often a running child is checked against the timeout.
const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// How long to wait for a killed child's pipes to close before giving up on them.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Everything one run needs besides the file list.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Path to the `node`-compatible executable under test.
    pub node: PathBuf,
    /// Root of the checked-out Node `test/` tree.
    pub tests: PathBuf,
    /// Per-file wall-clock limit.
    pub timeout: Duration,
    /// Number of files run concurrently.
    pub jobs: usize,
}

impl RunConfig {
    pub fn new(node: impl Into<PathBuf>, tests: impl Into<PathBuf>) -> Self {
        Self {
            node: node.into(),
            tests: tests.into(),
            timeout: Duration::from_secs(30),
            jobs: default_jobs(),
        }
    }

    /// Working directory Node's own runner uses: the parent of `test/`.
    ///
    /// `test/common/fixtures.js` resolves fixture paths from `__dirname`, but
    /// tests that spawn a child process pass their own `cwd` relative to the
    /// Node checkout root, so running from anywhere else changes results.
    pub fn working_dir(&self) -> PathBuf {
        self.tests
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.tests.clone())
    }
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|available| available.get())
        .unwrap_or(4)
        .min(8)
}

/// Rejects an executable that cannot possibly be spawned before a long run starts.
pub fn check_node_binary(node: &Path) -> Result<(), String> {
    if !node.exists() {
        return Err(format!("node executable {} does not exist", node.display()));
    }
    if !node.is_file() {
        return Err(format!("node executable {} is not a file", node.display()));
    }
    Ok(())
}

/// Runs every selected test and returns one result per file, in selection order.
///
/// `progress` is called as each file finishes, from the calling thread, so a
/// long run shows movement without interleaving partial lines.
pub fn run_all(
    config: &RunConfig,
    tests: &[TestFile],
    progress: &mut dyn FnMut(&FileResult),
) -> Vec<FileResult> {
    let working_dir = config.working_dir();
    // Node's runner is invoked from the checkout root with a `test/`-prefixed
    // script path, and some tests spawn `process.execPath` with the same shape.
    let script_prefix = config
        .tests
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "test".to_string());

    let (parallel, serial): (Vec<usize>, Vec<usize>) = (0..tests.len()).partition(|index| {
        let suite = tests[*index].relative.split('/').next().unwrap_or("");
        PARALLEL_SAFE_SUITES.contains(&suite)
    });

    let mut slots: Vec<Option<FileResult>> = tests.iter().map(|_| None).collect();
    for (indices, jobs) in [(parallel, config.jobs.max(1)), (serial, 1)] {
        if indices.is_empty() {
            continue;
        }
        let group = run_group(
            config,
            &working_dir,
            &script_prefix,
            tests,
            &indices,
            jobs,
            progress,
        );
        for (slot, result) in group {
            slots[slot] = Some(result);
        }
    }

    slots
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.unwrap_or_else(|| {
                FileResult::not_run(&tests[index].relative, "test was never run")
            })
        })
        .collect()
}

/// Runs `indices` with `jobs` workers and returns each result with its caller's index.
///
/// Workers hand back the slot they claimed, which is a position inside `indices`;
/// the result is translated back to the global index before it is returned, so
/// callers can store results positionally without knowing the grouping split.
fn run_group(
    config: &RunConfig,
    working_dir: &Path,
    script_prefix: &str,
    tests: &[TestFile],
    indices: &[usize],
    jobs: usize,
    progress: &mut dyn FnMut(&FileResult),
) -> Vec<(usize, FileResult)> {
    let cursor = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel();
    let mut finished = Vec::with_capacity(indices.len());

    if jobs <= 1 {
        for index in indices {
            let result = execute(config, working_dir, script_prefix, &tests[*index]);
            progress(&result);
            finished.push((*index, result));
        }
        return finished;
    }

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            let sender = sender.clone();
            let cursor = &cursor;
            scope.spawn(move || loop {
                let slot = cursor.fetch_add(1, Ordering::Relaxed);
                let Some(index) = indices.get(slot) else {
                    break;
                };
                let result = execute(config, working_dir, script_prefix, &tests[*index]);
                if sender.send((*index, result)).is_err() {
                    break;
                }
            });
        }
        // Every worker holds a clone, so drop ours before draining or the loop
        // would wait for a sender that is already idle.
        drop(sender);
        for (index, result) in receiver {
            progress(&result);
            finished.push((index, result));
        }
    });

    finished
}

/// Runs one file and records what happened.
fn execute(
    config: &RunConfig,
    working_dir: &Path,
    script_prefix: &str,
    test: &TestFile,
) -> FileResult {
    let script_arg = format!("{script_prefix}/{}", test.relative);
    // Node passes the file's `// Flags:` values before the script path, so a
    // flag the runtime does not support fails the test instead of being dropped.
    let mut command = Command::new(&config.node);
    command
        .args(&test.flags)
        .arg(&script_arg)
        .current_dir(working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Node's runner exports these so concurrent tests use distinct temp
        // directories. Runtimes that ignore unknown environment variables are
        // unaffected, and one that implements `process.env` gets a working tmpdir.
        .env("TEST_SERIAL_ID", "0")
        .env("TEST_THREAD_ID", "0")
        .env("TEST_PARALLEL", "0")
        .env("NODE_TEST_DIR", &config.tests)
        .env("GITHUB_STEP_SUMMARY", "");

    let started = Instant::now();
    configure_process_group(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let mut result = FileResult::not_run(&test.relative, format!("spawn failed: {error}"));
            result.flags = test.flags.clone();
            result.suite = suite_of(&test.relative);
            return result;
        }
    };

    let (pipe_sender, pipe_receiver) = mpsc::channel();
    if let Some(pipe) = child.stdout.take() {
        spawn_drain(pipe, STDOUT_HEAD_BYTES, Stream::Stdout, pipe_sender.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        spawn_drain(pipe, STDERR_HEAD_BYTES, Stream::Stderr, pipe_sender.clone());
    }
    drop(pipe_sender);

    let mut timed_out = false;
    let mut exit_code = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if started.elapsed() >= config.timeout {
                    kill_tree(&mut child);
                    timed_out = true;
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                kill_tree(&mut child);
                break;
            }
        }
    }

    let (stdout_head, stderr_head) = collect_output(pipe_receiver);
    let mut stderr_head = String::from_utf8_lossy(&stderr_head).trim_end().to_string();
    if timed_out && stderr_head.is_empty() {
        stderr_head = format!("timed out after {:?}", config.timeout);
    }

    FileResult {
        file: test.relative.clone(),
        suite: suite_of(&test.relative),
        passed: !timed_out && exit_code == Some(0),
        exit_code,
        duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        timed_out,
        flags: test.flags.clone(),
        stdout_head: String::from_utf8_lossy(&stdout_head).trim_end().to_string(),
        stderr_head,
    }
}

/// Which pipe a chunk of output came from.
#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

/// Starts a reader thread that forwards one pipe's first `cap` bytes.
fn spawn_drain(
    mut pipe: impl Read + Send + 'static,
    cap: usize,
    stream: Stream,
    sender: mpsc::Sender<(Stream, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let room = cap.saturating_sub(kept.len());
                    kept.extend_from_slice(&buffer[..read.min(room)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = sender.send((stream, kept));
    });
}

/// Waits for both readers, but never longer than [`DRAIN_GRACE`].
///
/// A killed test may have left a grandchild holding the pipe open. Blocking on
/// that would turn a 30-second timeout into an unbounded wait, so a pipe that
/// stays open past the grace period is abandoned with whatever it delivered.
fn collect_output(receiver: mpsc::Receiver<(Stream, Vec<u8>)>) -> (Vec<u8>, Vec<u8>) {
    let deadline = Instant::now() + DRAIN_GRACE;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut remaining = 2;
    while remaining > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left) {
            Ok((Stream::Stdout, bytes)) => stdout = bytes,
            Ok((Stream::Stderr, bytes)) => stderr = bytes,
            Err(_) => break,
        }
        remaining -= 1;
    }
    (stdout, stderr)
}

/// Puts the child in its own process group so the whole tree can be killed.
#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // A fresh group keeps `kill_tree` from reaching the harness itself, and a
    // test that forks children stays killable with one signal.
    command.process_group(0);
}

#[cfg(unix)]
fn kill_tree(child: &mut std::process::Child) {
    let _ = child.kill();
    // `kill` only reaches the direct child; signalling the whole group reaches
    // the descendants a test may have forked, which would otherwise keep the
    // output pipes open after the direct child is gone.
    // SAFETY: `kill` takes plain integers, performs no memory access, and a
    // stale process group simply reports ESRCH, which is ignored below.
    unsafe {
        let pid = child.id() as i32;
        if pid > 0 {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(not(unix))]
fn kill_tree(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Identifier for a run directory: `run-<epoch milliseconds>`.
///
/// Millisecond precision keeps two consecutive runs from colliding, and the
/// fixed width keeps lexicographic order equal to chronological order — which is
/// what the dashboard relies on to pick the newest result per file.
pub fn run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    format!("run-{millis:013}")
}

/// Result file name for a run, optionally annotated with a caller-supplied label.
///
/// The label only makes a run easier to recognise; ordering comes from the
/// zero-padded timestamp prefix, so re-running a labelled and an unlabelled run
/// in the same millisecond is the only way to tie.
pub fn result_file_name(run_id: &str, label: Option<&str>) -> String {
    match label {
        Some(label) if !label.is_empty() => {
            let safe: String = label
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            format!("{run_id}-{safe}.json")
        }
        _ => format!("{run_id}.json"),
    }
}

/// Writes one run's results as a JSON array, creating the directory if needed.
pub fn write_results(
    dir: &Path,
    file_name: &str,
    results: &[FileResult],
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join(file_name);
    let json = serde_json::to_string_pretty(results).map_err(|error| error.to_string())?;
    std::fs::write(&path, json).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny scoped Node-checkout stand-in; this crate has no dev-dependency for
    /// a temp-dir crate. The layout mirrors a real checkout: a `test/` directory
    /// whose parent is the working directory the runner uses.
    struct TempTree {
        root: PathBuf,
        tests: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("rn-harness-run-{}-{name}", std::process::id()));
            let tests = root.join("test");
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&tests).expect("mkdir");
            Self { root, tests }
        }

        fn script(&self, name: &str, body: &str) -> TestFile {
            let absolute = self.tests.join("parallel").join(name);
            std::fs::create_dir_all(absolute.parent().expect("parent")).expect("mkdir");
            std::fs::write(&absolute, body).expect("write");
            TestFile {
                relative: format!("parallel/{name}"),
                flags: Vec::new(),
            }
        }

        fn write(&self, relative: &str, body: &str) {
            let path = self.tests.join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, body).expect("write");
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn shell_config(tree: &TempTree) -> RunConfig {
        let mut config = RunConfig::new("/bin/sh", &tree.tests);
        config.timeout = Duration::from_secs(10);
        config.jobs = 1;
        config
    }

    #[test]
    fn a_zero_exit_is_a_pass() {
        let tree = TempTree::new("ok");
        let test = tree.script("test-ok.sh", "exit 0\n");
        let config = shell_config(&tree);
        let result = execute(&config, &config.working_dir(), "test", &test);
        assert!(result.passed, "{}", result.stderr_head);
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert_eq!(result.suite, "parallel");
    }

    #[test]
    fn a_nonzero_exit_keeps_stderr() {
        let tree = TempTree::new("fail");
        let test = tree.script("test-fail.sh", "echo boom >&2; exit 3\n");
        let config = shell_config(&tree);
        let result = execute(&config, &config.working_dir(), "test", &test);
        assert!(!result.passed);
        assert_eq!(result.exit_code, Some(3));
        assert!(
            result.stderr_head.contains("boom"),
            "{}",
            result.stderr_head
        );
    }

    #[test]
    fn a_hung_test_is_killed_at_the_timeout() {
        let tree = TempTree::new("hang");
        let test = tree.script("test-hang.sh", "sleep 30\n");
        let mut config = shell_config(&tree);
        config.timeout = Duration::from_millis(300);
        let result = execute(&config, &config.working_dir(), "test", &test);
        assert!(!result.passed);
        assert!(result.timed_out, "must record the timeout");
        assert!(
            result.duration_ms < 5_000,
            "must not wait for the child: {}ms",
            result.duration_ms
        );
        assert!(
            result.stderr_head.contains("timed out"),
            "{}",
            result.stderr_head
        );
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_does_not_deadlock() {
        let tree = TempTree::new("loud");
        let test = tree.script(
            "test-loud.sh",
            "i=0; while [ $i -lt 4000 ]; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done; exit 0\n",
        );
        let config = shell_config(&tree);
        let result = execute(&config, &config.working_dir(), "test", &test);
        assert!(
            result.passed,
            "exit={:?} timed_out={}",
            result.exit_code, result.timed_out
        );
        assert!(
            result.stdout_head.len() <= STDOUT_HEAD_BYTES,
            "kept {} bytes",
            result.stdout_head.len()
        );
    }

    #[test]
    fn a_missing_executable_is_reported_not_panicked() {
        let tree = TempTree::new("missing-node");
        let test = tree.script("test-ok.sh", "exit 0\n");
        let config = RunConfig::new("/nonexistent/rustnode", &tree.tests);
        let result = execute(&config, &config.working_dir(), "test", &test);
        assert!(!result.passed);
        assert!(
            result.stderr_head.contains("spawn failed"),
            "{}",
            result.stderr_head
        );
    }

    #[test]
    fn flags_reach_the_child_before_the_script() {
        let tree = TempTree::new("flags");
        tree.write("parallel/test-flags.sh", "true\n");
        let test = TestFile {
            relative: "parallel/test-flags.sh".into(),
            // `/bin/sh -x` echoes each command, so the trace proves ordering.
            flags: vec!["-x".into()],
        };
        let config = shell_config(&tree);
        let result = execute(&config, &config.working_dir(), "test", &test);
        assert!(result.passed, "{}", result.stderr_head);
        assert_eq!(result.flags, vec!["-x"]);
        assert!(
            result.stderr_head.contains("true"),
            "{}",
            result.stderr_head
        );
    }

    #[test]
    fn check_node_binary_rejects_a_missing_path() {
        let error = check_node_binary(Path::new("/nonexistent/rustnode")).expect_err("must fail");
        assert!(error.contains("does not exist"), "{error}");
        assert!(check_node_binary(Path::new("/bin/sh")).is_ok());
    }

    #[test]
    fn run_all_returns_results_in_selection_order() {
        let tree = TempTree::new("order");
        let tests: Vec<TestFile> = ["test-a.sh", "test-b.sh", "test-c.sh"]
            .iter()
            .map(|name| tree.script(name, "exit 0\n"))
            .collect();
        let config = shell_config(&tree);
        let mut seen = 0;
        let results = run_all(&config, &tests, &mut |_| seen += 1);
        assert_eq!(seen, 3, "progress fires once per file");
        let files: Vec<&str> = results.iter().map(|r| r.file.as_str()).collect();
        assert_eq!(
            files,
            vec![
                "parallel/test-a.sh",
                "parallel/test-b.sh",
                "parallel/test-c.sh"
            ]
        );
    }

    #[test]
    fn mixed_parallel_and_sequential_files_each_report_their_own_result() {
        // Regression: the serial group's positions are not global indices, so a
        // result keyed by position inside the group overwrote an unrelated file.
        // Every script exits with a distinct code so a misaligned result shows up
        // as the wrong exit code rather than coincidentally matching.
        let tree = TempTree::new("mixed");
        let mut tests = Vec::new();
        for (index, suite) in [
            "parallel",
            "es-module",
            "parallel",
            "sequential",
            "internet",
            "parallel",
            "sequential",
        ]
        .iter()
        .enumerate()
        {
            let relative = format!("{suite}/test-{index}.sh");
            let path = tree.tests.join(&relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, format!("exit {index}\n")).expect("write");
            tests.push(TestFile {
                relative,
                flags: Vec::new(),
            });
        }
        let mut config = shell_config(&tree);
        config.jobs = 3;
        let results = run_all(&config, &tests, &mut |_| {});

        assert_eq!(results.len(), tests.len());
        for (index, result) in results.iter().enumerate() {
            assert_eq!(
                result.file, tests[index].relative,
                "result {index} is attached to the wrong file"
            );
            assert_eq!(
                result.exit_code,
                Some(index as i32),
                "{} ran a different script",
                result.file
            );
        }
    }

    #[test]
    fn run_all_can_run_files_concurrently() {
        let tree = TempTree::new("concurrent");
        let tests: Vec<TestFile> = (0..8)
            .map(|index| tree.script(&format!("test-{index}.sh"), "sleep 0.2; exit 0\n"))
            .collect();
        let mut config = shell_config(&tree);
        config.jobs = 4;
        let started = Instant::now();
        let results = run_all(&config, &tests, &mut |_| {});
        assert!(results.iter().all(|r| r.passed));
        assert_eq!(results.len(), 8);
        // Serial would take ~1.6s; 4-wide should be well under half of that.
        assert!(
            started.elapsed() < Duration::from_millis(1_400),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn result_file_names_sort_chronologically() {
        let earlier = result_file_name("run-0000000100", None);
        let later = result_file_name("run-0000000200", None);
        assert!(earlier < later, "{earlier} !< {later}");
        assert_eq!(
            result_file_name("run-0000000100", Some("fs work")),
            "run-0000000100-fs-work.json"
        );
    }

    #[test]
    fn working_dir_is_the_parent_of_the_test_tree() {
        let config = RunConfig::new("/bin/sh", "/tmp/node/test");
        assert_eq!(config.working_dir(), PathBuf::from("/tmp/node"));
    }

    #[test]
    fn results_round_trip_through_a_file() {
        let tree = TempTree::new("round-trip");
        let config = shell_config(&tree);
        let test = tree.script("test-ok.sh", "exit 0\n");
        let results = run_all(&config, std::slice::from_ref(&test), &mut |_| {});
        let dir = tree.root.join("results");
        let path = write_results(&dir, "run-0000000001.json", &results).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        let parsed: Vec<FileResult> = serde_json::from_str(&text).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].passed);
    }
}
