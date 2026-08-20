//! A PAM module fixture used only by integration tests in this crate.
//!
//! The module intentionally exercises the full API surface that Task 7 validates:
//! user/service/rhost reads, env reads, token set/clear, secret operations, and
//! cleanup behavior for typed module data.

#[macro_use]
extern crate pamsm;

use pamsm::{
    Pam, PamData, PamError, PamFlags, PamLibExt, PamResult, PamSecretBytes, PamServiceModule,
};
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::str;

const FIXED_TOKEN: &[u8] = b"fixed-ci-dummy";
const EXPECTED_ENV_KEY: &str = "PAMSM_TEST";
const EXPECTED_ENV_VALUE: &str = "ready";
const SECRET_KEY: &str = "pamsm.test.secret";
const CLEANUP_KEY: &str = "pamsm.test.cleanup";
const INFO_TEXT: &str = "pamsm test info";

#[derive(Clone)]
struct ProbeCleanup(&'static str);

impl PamData for ProbeCleanup {
    fn cleanup(&self, _pam: Pam, flags: PamFlags, status: PamError) {
        let _ = append_trace(&format!("cleanup:{}:{:?}:{:?}", self.0, flags, status));
    }
}

macro_rules! hook {
    ($name:expr, $body:block) => {{
        log_hook($name, "entry");
        let result = { $body };
        if result == PamError::SUCCESS {
            log_hook($name, "exit-success");
        } else {
            log_hook($name, "exit-error");
        }
        result
    }};
}

fn log_dir() -> Option<PathBuf> {
    std::env::var_os("PAMSM_TEST_LOG_DIR").map(PathBuf::from)
}

fn run_case() -> String {
    std::env::var("PAMSM_TEST_CASE").unwrap_or_else(|_| "unknown".to_string())
}

fn append_trace(line: &str) -> std::io::Result<()> {
    let mut path = log_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    path.push("events.log");
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{} {}", run_case(), line)?;
    Ok(())
}

fn log_hook(hook: &'static str, stage: &'static str) {
    let _ = append_trace(&format!("hook::{hook}:{stage}"));
}

fn log_context(message: &str) {
    let _ = append_trace(&format!("context::{message}"));
}

fn log_secret() {
    let _ = append_trace(&format!("secret-key:{SECRET_KEY}"));
}

fn assert_env_and_items(pamh: &Pam, hook: &'static str) -> PamError {
    let env_value = match std::env::var(EXPECTED_ENV_KEY).ok() {
        Some(v) => v,
        None => {
            log_context(&format!("failure:{hook}:env-missing"));
            return PamError::SERVICE_ERR;
        }
    };
    if env_value != EXPECTED_ENV_VALUE {
        log_context(&format!("failure:{hook}:env-mismatch:{}", env_value));
        return PamError::SERVICE_ERR;
    }

    let user = match pamh.get_cached_user() {
        Ok(Some(u)) => u,
        Ok(None) => {
            log_context(&format!("failure:{hook}:user-missing"));
            return PamError::USER_UNKNOWN;
        }
        Err(e) => {
            log_context(&format!("failure:{hook}:user-error:{e:?}"));
            return e;
        }
    };
    let service = match pamh.get_service() {
        Ok(Some(s)) => s,
        Ok(None) => {
            log_context(&format!("failure:{hook}:service-missing"));
            return PamError::SERVICE_ERR;
        }
        Err(e) => {
            log_context(&format!("failure:{hook}:service-error:{e:?}"));
            return e;
        }
    };
    let rhost = match pamh.get_rhost() {
        Ok(Some(r)) => r,
        Ok(None) => {
            log_context(&format!("failure:{hook}:rhost-missing"));
            return PamError::SERVICE_ERR;
        }
        Err(e) => {
            log_context(&format!("failure:{hook}:rhost-error:{e:?}"));
            return e;
        }
    };
    log_context(&format!(
        "{hook} env={EXPECTED_ENV_VALUE} user={} service={} rhost={}",
        user.to_string_lossy(),
        service.to_string_lossy(),
        rhost.to_string_lossy()
    ));

    if pamh.info(INFO_TEXT).is_err() {
        return PamError::SERVICE_ERR;
    }
    PamError::SUCCESS
}

fn assert_token(text: &CStr) -> bool {
    text.to_bytes() == FIXED_TOKEN
}

fn exercise_token_cycle(pamh: &Pam) -> PamError {
    let token = match CString::new(str::from_utf8(FIXED_TOKEN).unwrap_or_default()) {
        Ok(token) => token,
        Err(_) => return PamError::SERVICE_ERR,
    };
    if pamh.set_authtok(&token).is_err() {
        return PamError::SERVICE_ERR;
    }
    let now = pamh.get_cached_authtok();
    match now {
        Ok(Some(value)) if assert_token(value) => {}
        Ok(None) | Err(_) => return PamError::SERVICE_ERR,
        _ => return PamError::SERVICE_ERR,
    }
    if pamh.clear_authtok().is_err() {
        return PamError::SERVICE_ERR;
    }
    if pamh.get_cached_authtok().unwrap_or(None).is_some() {
        return PamError::SERVICE_ERR;
    }
    PamError::SUCCESS
}

fn exercise_secret(pamh: &Pam) -> PamResult<()> {
    log_secret();
    pamh.send_secret(SECRET_KEY, PamSecretBytes::new(FIXED_TOKEN.to_vec()))?;
    let first = unsafe { pamh.get_secret(SECRET_KEY) }?;
    if first.expose() != FIXED_TOKEN {
        return Err(PamError::SERVICE_ERR);
    }
    pamh.send_secret(SECRET_KEY, PamSecretBytes::new(FIXED_TOKEN.to_vec()))?;
    let second = unsafe { pamh.get_secret(SECRET_KEY) }?;
    if second.expose() != FIXED_TOKEN {
        return Err(PamError::SERVICE_ERR);
    }
    Ok(())
}

fn exercise_cleanup_probe(pamh: &Pam, hook: &'static str) -> PamResult<()> {
    unsafe { pamh.send_data(CLEANUP_KEY, ProbeCleanup(hook))? };
    unsafe { pamh.send_data(CLEANUP_KEY, ProbeCleanup(hook))? };
    Ok(())
}

struct Module;

impl PamServiceModule for Module {
    fn authenticate(pamh: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        hook!("authenticate", {
            if assert_env_and_items(&pamh, "authenticate") != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_secret(&pamh).is_err() {
                return PamError::SERVICE_ERR;
            }
            if exercise_token_cycle(&pamh) != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_cleanup_probe(&pamh, "authenticate").is_err() {
                return PamError::SERVICE_ERR;
            }
            PamError::SUCCESS
        })
    }

    fn setcred(pamh: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        hook!("setcred", {
            if assert_env_and_items(&pamh, "setcred") != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_secret(&pamh).is_err() {
                return PamError::SERVICE_ERR;
            }
            if exercise_cleanup_probe(&pamh, "setcred").is_err() {
                return PamError::SERVICE_ERR;
            }
            PamError::SUCCESS
        })
    }

    fn acct_mgmt(pamh: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        hook!("acct_mgmt", {
            if assert_env_and_items(&pamh, "acct_mgmt") != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_secret(&pamh).is_err() {
                return PamError::SERVICE_ERR;
            }
            if exercise_cleanup_probe(&pamh, "acct_mgmt").is_err() {
                return PamError::SERVICE_ERR;
            }
            PamError::SUCCESS
        })
    }

    fn open_session(pamh: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        hook!("open_session", {
            if assert_env_and_items(&pamh, "open_session") != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_secret(&pamh).is_err() {
                return PamError::SERVICE_ERR;
            }
            if exercise_cleanup_probe(&pamh, "open_session").is_err() {
                return PamError::SERVICE_ERR;
            }
            PamError::SUCCESS
        })
    }

    fn close_session(pamh: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        hook!("close_session", {
            if assert_env_and_items(&pamh, "close_session") != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_secret(&pamh).is_err() {
                return PamError::SERVICE_ERR;
            }
            if exercise_cleanup_probe(&pamh, "close_session").is_err() {
                return PamError::SERVICE_ERR;
            }
            PamError::SUCCESS
        })
    }

    fn chauthtok(pamh: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        hook!("chauthtok", {
            if assert_env_and_items(&pamh, "chauthtok") != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_secret(&pamh).is_err() {
                return PamError::SERVICE_ERR;
            }
            if exercise_token_cycle(&pamh) != PamError::SUCCESS {
                return PamError::SERVICE_ERR;
            }
            if exercise_cleanup_probe(&pamh, "chauthtok").is_err() {
                return PamError::SERVICE_ERR;
            }
            PamError::SUCCESS
        })
    }
}

pam_module!(Module);
