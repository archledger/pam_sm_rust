#![allow(clippy::cognitive_complexity)]
#![allow(clippy::similar_names)]

//! Integration tests through a real PAM stack:
//! one test per entrypoint type using `pam_wrapper` + `pamtester`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const EXPECTED_INFO_MESSAGE: &str = "pamsm test info";
const EXPECTED_ENV_VALUE: &str = "ready";
const SECRET_KEYWORD: &str = "fixed-ci-dummy";

struct Harness {
    wrapper: PathBuf,
    module: PathBuf,
    service_dir: PathBuf,
    logs_root: PathBuf,
    case_root: PathBuf,
}

impl Harness {
    fn try_new(name: &str) -> Option<Self> {
        let wrapper = match wrapper_lib() {
            Some(path) => path,
            None => {
                eprintln!(
                    "skipping: libpam_wrapper.so not found \
(Fedora: dnf install pam_wrapper; Ubuntu: apt-get install libpam-wrapper; \
or set PAM_WRAPPER_SO)"
                );
                return None;
            }
        };
        if !pamtester_available() {
            eprintln!("skipping: pamtester binary not available");
            return None;
        }

        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
        let root = target_dir.join("pamsm-test-logs");
        let pid = std::process::id();
        let case_root = root.join(format!("pamwrap-{pid}-{name}"));

        fs::create_dir_all(&case_root).unwrap();

        Some(Harness {
            wrapper,
            module: built_module(),
            service_dir: case_root.join("services"),
            logs_root: case_root.join("logs"),
            case_root,
        })
    }

    fn write_service(&self, service: &str, lines: &[String]) {
        fs::create_dir_all(&self.service_dir).unwrap();
        let mut body = lines.join("\n");
        body.push('\n');
        fs::write(self.service_dir.join(service), body).unwrap();
        fs::write(
            self.service_dir.join("other"),
            [
                "auth required pam_deny.so",
                "account required pam_deny.so",
                "password required pam_deny.so",
                "session required pam_deny.so",
            ]
            .join("\n"),
        )
        .unwrap();
    }

    fn run(&self, service: &str, op: &str, username: &str) -> (bool, String) {
        fs::create_dir_all(&self.logs_root).unwrap();
        let mut cmd = Command::new("pamtester");
        cmd.arg("-I").arg("rhost=127.0.0.1");
        cmd.arg(service).arg(username).arg(op);
        cmd.env("LD_PRELOAD", &self.wrapper);
        // Under `-Zsanitizer=address` the fixture cdylib expects the ASan
        // runtime to exist in the host process. pamtester is uninstrumented,
        // so the runtime must be preloaded ahead of pam_wrapper. The ASan job
        // sets this to the compiler-rt runtime; nothing else needs it.
        if let Ok(prepend) = std::env::var("PAMSM_TEST_PREPEND_PRELOAD") {
            cmd.env(
                "LD_PRELOAD",
                format!("{prepend}:{}", self.wrapper.display()),
            );
            // pam_wrapper dlopens service modules with RTLD_DEEPBIND, which
            // the ASan runtime refuses; it offers this switch for that case.
            cmd.env("PAM_WRAPPER_DISABLE_DEEPBIND", "1");
        }
        cmd.env("PAM_WRAPPER", "1");
        cmd.env("PAM_WRAPPER_SERVICE_DIR", &self.service_dir);
        cmd.env("PAMSM_TEST", EXPECTED_ENV_VALUE);
        cmd.env("PAMSM_TEST_LOG_DIR", &self.logs_root);
        cmd.env("PAMSM_TEST_CASE", format!("{username}:{op}"));
        cmd.env_remove("PAM_AUTHTOK");

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().expect("spawn pamtester");
        let mut stdout = String::new();
        stdout.push_str(&String::from_utf8_lossy(&output.stdout));
        stdout.push_str(&String::from_utf8_lossy(&output.stderr));

        let log = self.case_root.join(format!("{op}-pamtester.log"));
        fs::write(&log, &stdout).unwrap();
        (output.status.success(), stdout)
    }

    fn service_lines(&self) -> Vec<String> {
        vec![
            format!("auth required {}", self.module.display()),
            format!("account required {}", self.module.display()),
            format!("password required {}", self.module.display()),
            format!("session required {}", self.module.display()),
        ]
    }
}

fn wrapper_lib() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PAM_WRAPPER_SO") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    [
        "/usr/lib64/libpam_wrapper.so",
        "/usr/lib/x86_64-linux-gnu/libpam_wrapper.so",
        "/usr/lib/aarch64-linux-gnu/libpam_wrapper.so",
        "/usr/lib/libpam_wrapper.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn pamtester_available() -> bool {
    Command::new("pamtester")
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn built_module() -> PathBuf {
    if let Some(path) = locate_module() {
        return path.canonicalize().unwrap_or(path);
    }

    panic!("failed to locate libtest_module.so; run `cargo build --example test_module --features libpam` first");
}

fn locate_module() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps) = exe.parent() {
            candidates.push(deps.to_path_buf());
            if let Some(profile_dir) = deps.parent() {
                candidates.push(profile_dir.to_path_buf());
                // Under an explicit `--target <triple>` build the example
                // cdylib lands in <target>/<triple>/<profile>/examples.
                candidates.push(profile_dir.join("examples"));
            }
        }
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let base = PathBuf::from(target_dir);
        let target = if base.is_absolute() {
            base
        } else {
            workspace.join(base)
        };
        candidates.push(target.join("debug").join("examples"));
        candidates.push(target.join("debug").join("deps"));
        candidates.push(target.join("debug"));
        candidates.push(target.join("release").join("examples"));
        candidates.push(target.join("release").join("deps"));
        candidates.push(target.join("release"));
    }
    candidates.push(workspace.join("target").join("debug").join("examples"));
    candidates.push(workspace.join("target").join("debug").join("deps"));
    candidates.push(workspace.join("target").join("debug"));
    candidates.push(workspace.join("target").join("release").join("examples"));
    candidates.push(workspace.join("target").join("release").join("deps"));
    candidates.push(workspace.join("target").join("release"));

    for dir in &candidates {
        if let Some(module) = find_module_in_dir(dir) {
            return Some(module);
        }
    }

    None
}

fn find_module_in_dir(dir: &Path) -> Option<PathBuf> {
    let exact = dir.join("libtest_module.so");
    if exact.exists() {
        return Some(exact);
    }
    let exact_alt = dir.join("libtest_module");
    if exact_alt.exists() {
        return Some(exact_alt);
    }

    let entries = fs::read_dir(dir).ok()?;
    let mut matches: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|ent| ent.path())
        .filter(|path| {
            let is_file = path.is_file();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            is_file && name.starts_with("libtest_module-") && name.ends_with(".so")
        })
        .collect();
    matches.sort();
    matches.into_iter().next()
}

fn trace_file(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn read_trace(harness: &Harness) -> String {
    let path = harness.logs_root.join("events.log");
    trace_file(&path).unwrap_or_default()
}

fn run_for_op(op: &str, user: &str) -> Option<(bool, String, String)> {
    let h = Harness::try_new(op)?;
    let service = format!("pamsm-{op}");
    h.write_service(&service, &h.service_lines());
    let (ok, out) = h.run(&service, op, user);
    let trace = read_trace(&h);
    Some((ok, out, trace))
}

fn assert_trace_and_output(op: &str, out: &str, trace: &str) {
    assert!(
        out.contains(EXPECTED_INFO_MESSAGE),
        "{}",
        "missing pamsm info text"
    );
    assert!(
        !out.contains(SECRET_KEYWORD),
        "token must not leak into output"
    );
    assert!(
        !trace.contains(SECRET_KEYWORD),
        "token must not leak into trace logs"
    );
    assert!(
        trace.contains(&format!("hook::{op}:entry")),
        "{}",
        format!("missing hook entry for {op}")
    );
    assert!(
        trace.contains(&format!("hook::{op}:exit-success")),
        "{}",
        format!("missing hook success marker for {op}")
    );
    assert!(trace.contains("context::"), "missing context trace");
    assert!(trace.contains("cleanup:"), "missing cleanup trace");
    assert!(
        trace.contains("pamsm.test.secret"),
        "expected secret key marker in trace"
    );
    assert!(
        trace.contains("user=tester"),
        "expected fixture to assert PAM user"
    );
    assert!(
        trace.contains("service=pamsm-"),
        "expected fixture to assert PAM service"
    );
    assert!(
        trace.contains("rhost=127.0.0.1"),
        "expected fixture to assert PAM rhost"
    );
    assert!(
        trace.contains(&format!("cleanup:{op}")),
        "{}",
        format!("expected cleanup callback for {op}")
    );
    assert!(trace.contains("env=ready"), "expected env marker");
}

#[test]
#[ignore = "needs pam_wrapper and pamtester (CI installs them); see test header"]
fn pamwrap_authenticate_hook() {
    let Some((ok, out, trace)) = run_for_op("authenticate", "tester") else {
        return;
    };
    assert!(ok, "{}", out);
    assert_trace_and_output("authenticate", &out, &trace);
}

#[test]
#[ignore = "needs pam_wrapper and pamtester (CI installs them); see test header"]
fn pamwrap_setcred_hook() {
    let Some((ok, out, trace)) = run_for_op("setcred", "tester") else {
        return;
    };
    assert!(ok, "{}", out);
    assert_trace_and_output("setcred", &out, &trace);
}

#[test]
#[ignore = "needs pam_wrapper and pamtester (CI installs them); see test header"]
fn pamwrap_account_mgmt_hook() {
    let Some((ok, out, trace)) = run_for_op("acct_mgmt", "tester") else {
        return;
    };
    assert!(ok, "{}", out);
    assert_trace_and_output("acct_mgmt", &out, &trace);
}

#[test]
#[ignore = "needs pam_wrapper and pamtester (CI installs them); see test header"]
fn pamwrap_open_session_hook() {
    let Some((ok, out, trace)) = run_for_op("open_session", "tester") else {
        return;
    };
    assert!(ok, "{}", out);
    assert_trace_and_output("open_session", &out, &trace);
}

#[test]
#[ignore = "needs pam_wrapper and pamtester (CI installs them); see test header"]
fn pamwrap_close_session_hook() {
    let Some((ok, out, trace)) = run_for_op("close_session", "tester") else {
        return;
    };
    assert!(ok, "{}", out);
    assert_trace_and_output("close_session", &out, &trace);
}

#[test]
#[ignore = "needs pam_wrapper and pamtester (CI installs them); see test header"]
fn pamwrap_chauthtok_hook() {
    let Some((ok, out, trace)) = run_for_op("chauthtok", "tester") else {
        return;
    };
    assert!(ok, "{}", out);
    assert_trace_and_output("chauthtok", &out, &trace);
}
