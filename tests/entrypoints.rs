#[macro_use]
extern crate pamsm;

use pamsm::{Pam, PamError, PamFlags, PamServiceModule};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

struct Hooks;

impl PamServiceModule for Hooks {
    fn authenticate(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::IGNORE
    }

    fn acct_mgmt(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::AUTH_ERR
    }

    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SESSION_ERR
    }

    fn close_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::CRED_ERR
    }

    fn chauthtok(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::AUTHTOK_ERR
    }
}

pam_module!(Hooks);

type Entry = unsafe extern "C" fn(*mut c_void, c_int, c_int, *const *const c_char) -> c_int;

fn entries() -> [(Entry, PamError); 6] {
    [
        (pam_sm_authenticate, PamError::SUCCESS),
        (pam_sm_setcred, PamError::IGNORE),
        (pam_sm_acct_mgmt, PamError::AUTH_ERR),
        (pam_sm_open_session, PamError::SESSION_ERR),
        (pam_sm_close_session, PamError::CRED_ERR),
        (pam_sm_chauthtok, PamError::AUTHTOK_ERR),
    ]
}

#[test]
fn every_exported_entrypoint_uses_checked_dispatch() {
    let handle = ptr::NonNull::<u8>::dangling().as_ptr() as *mut c_void;

    for (entry, expected) in entries() {
        // SAFETY: the opaque handle is non-null; zero arguments require no
        // argv array; each hook in this fixture ignores the handle.
        let normal = unsafe { entry(handle, 0, 0, ptr::null()) };
        assert_eq!(normal, expected as c_int);

        // SAFETY: a null handle is deliberately supplied to verify rejection
        // before hook invocation or pointer dereference.
        let rejected = unsafe { entry(ptr::null_mut(), 0, 0, ptr::null()) };
        assert_eq!(rejected, PamError::ABORT as c_int);
    }
}
