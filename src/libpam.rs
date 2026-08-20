#![allow(dead_code)]

use crate::module_data::{cleanup_boxed, contain_cleanup, PamSecretBytes};
use crate::pam::{Pam, PamError, PamFlags};
use crate::pam_types::{LogLvl, PamConstHandle, PamHandle, PamItemType, PamMsgStyle};
use std::ffi::{CStr, CString, NulError};
use std::ops::Deref;
use std::option::Option;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

pub type PamResult<T> = Result<T, PamError>;

/// Trait to implement for data stored with pam using [`PamLibExt::send_data`]
/// in order to provide a cleanup callback.
/// # Example
/// ```
/// extern crate pamsm;
/// use pamsm::{Pam, PamData, PamError, PamFlags};
/// use std::fs::write;
///
/// struct Token([u8; 32]);
///
/// impl PamData for Token {
///     fn cleanup(&self, _pam: Pam, flags: PamFlags, status: PamError) {
///         if !flags.contains(PamFlags::DATA_REPLACE) && status == PamError::SUCCESS {
///             match write(".token.bin", self.0) {
///                 Ok(_) => (),
///                 Err(err) => {
///                     if !flags.contains(PamFlags::DATA_SILENT) {
///                         println!("Error persisting token : {:?}", err);
///                     }
///                 }
///             };
///         }
///     }
/// }
/// ```
pub trait PamData {
    /// The cleanup method will be called before the data is dropped by pam.
    /// See `pam_set_data (3)`
    fn cleanup(&self, _pam: Pam, _flags: PamFlags, _status: PamError) {}
}

/// Blanket implementation for types that implement `Deref<T>` when `T` implements `PamData`.
impl<T: PamData, U> PamData for U
where
    U: Deref<Target = T>,
{
    fn cleanup(&self, pam: Pam, flags: PamFlags, status: PamError) {
        T::cleanup(self, pam, flags, status)
    }
}

impl PamError {
    fn to_result<T>(self, ok: T) -> PamResult<T> {
        if self == PamError::SUCCESS {
            Ok(ok)
        } else {
            Err(self)
        }
    }
}

/// This contains a private marker trait, used to seal private traits.
mod private {
    pub trait Sealed {}
    impl Sealed for super::Pam {}
}

struct PamApi {
    get_item: unsafe extern "C" fn(PamConstHandle, c_int, *mut *const c_void) -> c_int,
    get_user: unsafe extern "C" fn(PamHandle, *mut *const c_char, *const c_char) -> c_int,
    get_authtok: unsafe extern "C" fn(PamHandle, c_int, *mut *const c_char, *const c_char) -> c_int,
    set_item: unsafe extern "C" fn(PamHandle, c_int, *const c_void) -> c_int,
    putenv: unsafe extern "C" fn(PamHandle, *const c_char) -> c_int,
}

const PAM_API: PamApi = PamApi {
    get_item: ffi::pam_get_item,
    get_user: ffi::pam_get_user,
    get_authtok: ffi::pam_get_authtok,
    set_item: ffi::pam_set_item,
    putenv: ffi::pam_putenv,
};

/// Retrieve an optional C-string item through one PAM API table.
///
/// # Safety
///
/// `handle` must be a live PAM handle accepted by `api`; on success, a
/// non-null output must remain a valid C string for `'a`.
unsafe fn get_item_with<'a>(
    api: &PamApi,
    handle: PamHandle,
    item_type: PamItemType,
) -> PamResult<Option<&'a CStr>> {
    let mut output: *const c_void = ptr::null();
    // SAFETY: the caller provides the live handle required by `api`, and
    // `output` is writable for the duration of this synchronous call.
    let status = unsafe { (api.get_item)(handle, item_type as c_int, &mut output) };
    let status = PamError::new(status);
    if status != PamError::SUCCESS {
        return Err(status);
    }
    if output.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller guarantees a successful non-null output remains a
    // valid C string for the returned lifetime.
    Ok(Some(unsafe { CStr::from_ptr(output as *const c_char) }))
}

/// Retrieve the required user output through one PAM API table.
///
/// # Safety
///
/// `handle` must be a live PAM handle accepted by `api`; on success, a
/// non-null output must remain a valid C string for `'a`. `prompt` must be null
/// or a valid C string for the duration of the call.
unsafe fn get_user_with<'a>(
    api: &PamApi,
    handle: PamHandle,
    prompt: *const c_char,
) -> PamResult<&'a CStr> {
    let mut output: *const c_char = ptr::null();
    // SAFETY: the caller provides the live handle and valid optional prompt;
    // `output` is writable for the duration of this synchronous call.
    let status = unsafe { (api.get_user)(handle, &mut output, prompt) };
    // SAFETY: the caller guarantees a successful non-null output remains a
    // valid C string for the returned lifetime.
    unsafe { required_cstr(status, output) }
}

/// Retrieve the required authentication-token output through one API table.
///
/// # Safety
///
/// `handle` must be a live PAM handle accepted by `api`; on success, a
/// non-null output must remain a valid C string for `'a`. `prompt` must be null
/// or a valid C string for the duration of the call.
unsafe fn get_authtok_with<'a>(
    api: &PamApi,
    handle: PamHandle,
    item_type: PamItemType,
    prompt: *const c_char,
) -> PamResult<&'a CStr> {
    let mut output: *const c_char = ptr::null();
    // SAFETY: the caller provides the live handle and valid optional prompt;
    // `output` is writable for the duration of this synchronous call.
    let status = unsafe { (api.get_authtok)(handle, item_type as c_int, &mut output, prompt) };
    // SAFETY: the caller guarantees a successful non-null output remains a
    // valid C string for the returned lifetime.
    unsafe { required_cstr(status, output) }
}

/// Convert a required C-string output only after checking its PAM status.
///
/// # Safety
///
/// On success, a non-null `output` must remain a valid C string for `'a`.
unsafe fn required_cstr<'a>(status: c_int, output: *const c_char) -> PamResult<&'a CStr> {
    let status = PamError::new(status);
    if status != PamError::SUCCESS {
        return Err(status);
    }
    if output.is_null() {
        return Err(PamError::SYSTEM_ERR);
    }
    // SAFETY: the caller guarantees a successful non-null output remains a
    // valid C string for the returned lifetime.
    Ok(unsafe { CStr::from_ptr(output) })
}

/// Convert a required typed output only after checking its PAM status.
///
/// # Safety
///
/// On success, a non-null `output` must point to a live immutable `T` for `'a`.
unsafe fn required_data<'a, T>(status: c_int, output: *const c_void) -> PamResult<&'a T> {
    let status = PamError::new(status);
    if status != PamError::SUCCESS {
        return Err(status);
    }
    if output.is_null() {
        return Err(PamError::SYSTEM_ERR);
    }
    // SAFETY: the caller guarantees a successful non-null output points to a
    // live immutable `T` for the returned lifetime.
    Ok(unsafe { &*(output as *const T) })
}

/// Set one PAM item through an injected API table.
///
/// # Safety
///
/// `handle` and `item` must satisfy the selected PAM item's C contract.
unsafe fn set_item_with(
    api: &PamApi,
    handle: PamHandle,
    item_type: PamItemType,
    item: *const c_void,
) -> PamResult<()> {
    // SAFETY: the caller provides the live handle and item pointer required by
    // the selected item type.
    let status = unsafe { (api.set_item)(handle, item_type as c_int, item) };
    PamError::new(status).to_result(())
}

/// Mutate the PAM environment through an injected API table.
///
/// # Safety
///
/// `handle` must be live and `name_value` must point to a valid C string for
/// the duration of the call.
unsafe fn putenv_with(api: &PamApi, handle: PamHandle, name_value: *const c_char) -> PamResult<()> {
    // SAFETY: the caller provides the live handle and valid C string required
    // by `pam_putenv`.
    let status = unsafe { (api.putenv)(handle, name_value) };
    PamError::new(status).to_result(())
}

type PromptInfoFn = unsafe fn(PamHandle, *const c_char) -> c_int;

/// Display response-free informational text through an injected helper.
///
/// # Safety
///
/// `handle` must be live and `message` must point to a valid C string for the
/// duration of the call.
unsafe fn info_with(
    prompt: PromptInfoFn,
    handle: PamHandle,
    message: *const c_char,
) -> PamResult<()> {
    // SAFETY: the caller provides the live handle and valid C string required
    // by the response-free prompt helper.
    let status = unsafe { prompt(handle, message) };
    PamError::new(status).to_result(())
}

/// Call Linux-PAM's variadic prompt only in response-free informational mode.
///
/// # Safety
///
/// `handle` must be live and `message` must point to a valid C string for the
/// duration of the call.
unsafe fn prompt_info(handle: PamHandle, message: *const c_char) -> c_int {
    let format = c"%s".as_ptr();
    // SAFETY: the caller provides the live handle and valid message; TEXT_INFO
    // expects no response, and `format` consumes exactly one C-string argument.
    unsafe {
        ffi::pam_prompt(
            handle,
            PamMsgStyle::TEXT_INFO as c_int,
            ptr::null_mut(),
            format,
            message,
        )
    }
}

impl Pam {
    // End users should call the item specific methods
    fn get_cstr_item(&self, item_type: PamItemType) -> PamResult<Option<&CStr>> {
        match item_type {
            PamItemType::CONV | PamItemType::FAIL_DELAY | PamItemType::XAUTHDATA => {
                panic!("Error, get_cstr_item can only be used with pam item returning c-strings")
            }
            _ => (),
        }
        // SAFETY: `self.0` is the live handle supplied by Linux-PAM; supported
        // string items remain allocated for the PAM transaction lifetime.
        unsafe { get_item_with(&PAM_API, self.0, item_type) }
    }
}

/// Extension trait over `Pam`, usually provided by the `libpam` shared library.
pub trait PamLibExt: private::Sealed {
    /// Get the username. If the PAM_USER item is not set, this function
    /// prompts for a username (like get_authtok).
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte.
    /// A successful PAM reply with no username is reported as
    /// `PamError::SYSTEM_ERR` (fail-closed), so `Ok(None)` is not produced.
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    /// Get the username, i.e. the PAM_USER item. If it's not set return None.
    fn get_cached_user(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token.
    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached old authentication token.
    fn get_cached_oldauthtok(&self) -> PamResult<Option<&CStr>>;

    /// Get the cached authentication token or prompt the user for one if there isn't any.
    /// Returns PamError::SERVICE_ERR if the prompt contains any null byte
    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>>;

    fn set_authtok(&self, authtok: &CString) -> PamResult<()>;

    /// Remove the cached authentication token from this PAM transaction.
    ///
    /// # Errors
    ///
    /// Returns the error reported by `pam_set_item` when PAM cannot clear the
    /// token.
    fn clear_authtok(&self) -> PamResult<()>;

    /// Get the remote hostname.
    fn get_rhost(&self) -> PamResult<Option<&CStr>>;

    /// Get the remote username.
    fn get_ruser(&self) -> PamResult<Option<&CStr>>;

    /// Get the service name.
    fn get_service(&self) -> PamResult<Option<&CStr>>;

    /// Display an informational message through the PAM conversation.
    ///
    /// # Errors
    ///
    /// Returns [`PamError::SERVICE_ERR`] if `message` contains a null byte, or
    /// the error reported by `pam_prompt` when the conversation fails.
    fn info(&self, message: &str) -> PamResult<()>;

    /// Get a variable from the pam environment list.
    fn getenv(&self, name: &str) -> PamResult<Option<&CStr>>;

    /// Put a variable in the pam environment list.
    /// `name_value` takes for form documented in pam_putent(3) :
    ///
    /// - `NAME=value` will set variable `NAME` to value `value`
    /// - `NAME=` will set variable `NAME` to an empty value
    /// - `NAME` will unset the variable `NAME`
    fn putenv(&self, name_value: &str) -> PamResult<()>;

    /// Send data to be stored by the pam library under the name `module_name`.
    /// The data can then be retrieved from a different
    /// callback in this module, or even by a different module
    /// using [`retrieve_data<T>`][Self::retrieve_data].
    ///
    /// When this method is called a second time with the same `module_name`, the method
    /// [`PamData::cleanup`] is called on the data previously stored.
    /// The same happens when the application calls `pam_end (3)`
    ///
    /// # Safety
    /// The same `module_name` must not be shared with typed data of another
    /// concrete type.
    unsafe fn send_data<T: PamData + Clone + Send>(
        &self,
        module_name: &str,
        data: T,
    ) -> PamResult<()>;

    /// Retrieve data previously stored with [`send_data<T>`][Self::send_data].
    ///
    /// Note that the result is a _copy_ of the data and not a shared reference,
    /// which differs from the behavior of the underlying `pam_get_data (3)` function.
    ///
    /// If you want to share the data instead you can wrap it in [`Arc`][std::sync::Arc].
    /// # Safety
    /// The type parameter `T` must be the same as the one used in
    /// [`send_data<T>`][Self::send_data] with the name `module_name`.
    ///
    unsafe fn retrieve_data<T: PamData + Clone + Send>(&self, module_name: &str) -> PamResult<T>;

    /// Store owned secret bytes in this PAM transaction.
    ///
    /// Ownership transfers to PAM only when `pam_set_data` succeeds. The
    /// secret is zeroized before release on replacement, transaction end, or
    /// registration failure.
    fn send_secret(&self, key: &str, value: PamSecretBytes) -> PamResult<()>;

    /// Borrow secret bytes previously stored with [`send_secret`][Self::send_secret].
    ///
    /// # Safety
    ///
    /// `key` must identify a value registered by `send_secret`, and that value
    /// must not be replaced while the returned borrow is live.
    unsafe fn get_secret<'a>(&'a self, key: &str) -> PamResult<&'a PamSecretBytes>;

    /// Send a message to syslog.
    fn syslog(&self, lvl: LogLvl, msg: &str) -> PamResult<()>;
}

impl From<NulError> for PamError {
    fn from(_: NulError) -> PamError {
        PamError::SERVICE_ERR
    }
}

impl PamLibExt for Pam {
    fn get_user(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = match prompt {
            None => None,
            Some(p) => Some(CString::new(p)?),
        };
        // SAFETY: `self.0` is the live PAM handle; `cprompt` remains allocated
        // for the synchronous call, and Linux-PAM owns the returned user.
        unsafe {
            get_user_with(
                &PAM_API,
                self.0,
                cprompt.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            )
            .map(Some)
        }
    }

    fn get_cached_user(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::USER)
    }

    fn get_cached_authtok(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::AUTHTOK)
    }

    fn get_cached_oldauthtok(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::OLDAUTHTOK)
    }

    fn get_authtok(&self, prompt: Option<&str>) -> PamResult<Option<&CStr>> {
        let cprompt = match prompt {
            None => None,
            Some(p) => Some(CString::new(p)?),
        };
        // SAFETY: `self.0` is the live PAM handle; `cprompt` remains allocated
        // for the synchronous call, and Linux-PAM owns the returned token.
        unsafe {
            get_authtok_with(
                &PAM_API,
                self.0,
                PamItemType::AUTHTOK,
                cprompt.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
            )
            .map(Some)
        }
    }

    fn set_authtok(&self, authtok: &CString) -> PamResult<()> {
        // SAFETY: `self.0` is the live PAM handle and `authtok` is a valid C
        // string that remains allocated for the synchronous copy.
        unsafe {
            set_item_with(
                &PAM_API,
                self.0,
                PamItemType::AUTHTOK,
                authtok.as_ptr() as *const c_void,
            )
        }
    }

    fn clear_authtok(&self) -> PamResult<()> {
        // SAFETY: `self.0` is the live handle supplied by libpam, AUTHTOK is a
        // string item, and Linux-PAM defines a null item pointer as clearing it.
        unsafe { set_item_with(&PAM_API, self.0, PamItemType::AUTHTOK, ptr::null()) }
    }

    fn get_rhost(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::RHOST)
    }

    fn get_ruser(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::RUSER)
    }

    fn get_service(&self) -> PamResult<Option<&CStr>> {
        self.get_cstr_item(PamItemType::SERVICE)
    }

    fn info(&self, message: &str) -> PamResult<()> {
        let message = CString::new(message)?;
        // SAFETY: `self.0` is the live handle supplied by Linux-PAM and
        // `message` remains allocated for the synchronous call.
        unsafe { info_with(prompt_info, self.0, message.as_ptr()) }
    }

    fn getenv(&self, name: &str) -> PamResult<Option<&CStr>> {
        let cname = CString::new(name)?;
        // SAFETY: `self.0` is the live PAM handle and `cname` remains
        // allocated for the synchronous call.
        let cenv = unsafe { ffi::pam_getenv(self.0, cname.as_ptr()) };

        if cenv.is_null() {
            Ok(None)
        } else {
            // SAFETY: Linux-PAM returned a non-null environment string owned
            // by the live PAM transaction.
            unsafe { Ok(Some(CStr::from_ptr(cenv))) }
        }
    }

    fn putenv(&self, name_value: &str) -> PamResult<()> {
        let cenv = CString::new(name_value)?;
        // SAFETY: `self.0` is the live PAM handle and `cenv` remains allocated
        // for the synchronous call.
        unsafe { putenv_with(&PAM_API, self.0, cenv.as_ptr()) }
    }

    unsafe fn send_data<T: PamData + Clone + Send>(
        &self,
        module_name: &str,
        data: T,
    ) -> PamResult<()> {
        let module_name = CString::new(module_name)?;
        let data = Box::into_raw(Box::new(data)) as *mut c_void;
        // SAFETY: `self.0` is the live PAM handle, `module_name` remains live
        // for the synchronous call, and `data` owns one boxed `T` whose
        // callback consumes it at most once after successful registration.
        let status = PamError::new(unsafe {
            ffi::pam_set_data(
                self.0,
                module_name.as_ptr(),
                data,
                Some(pam_data_cleanup::<T>),
            )
        });
        // SAFETY: `data` is still the unique pointer returned by
        // `Box::into_raw`; PAM owns it only when `status` is SUCCESS.
        unsafe { finish_store::<T>(status, data) }
    }

    unsafe fn retrieve_data<T: PamData + Clone + Send>(&self, module_name: &str) -> PamResult<T> {
        let module_name = CString::new(module_name)?;
        let mut data_ptr: *const c_void = ptr::null();
        // SAFETY: `self.0` is the live PAM handle, `module_name` remains live
        // for the synchronous call, and `data_ptr` is writable output storage.
        let status = unsafe { ffi::pam_get_data(self.0, module_name.as_ptr(), &mut data_ptr) };
        // SAFETY: the caller guarantees this key was registered as `T`; PAM
        // owns that value for the transaction lifetime.
        match unsafe { required_data::<T>(status, data_ptr) } {
            Ok(data) => Ok(data.clone()),
            Err(error) => Err(error),
        }
    }

    fn send_secret(&self, key: &str, value: PamSecretBytes) -> PamResult<()> {
        let key = CString::new(key)?;
        let data = Box::into_raw(Box::new(value)) as *mut c_void;
        // SAFETY: `self.0` is the live PAM handle, `key` remains live for the
        // synchronous call, `data` owns one boxed secret, and the callback
        // consumes that pointer at most once after successful registration.
        let status = unsafe {
            PamError::new(ffi::pam_set_data(
                self.0,
                key.as_ptr(),
                data,
                Some(pam_secret_cleanup),
            ))
        };
        // SAFETY: `data` is still the unique pointer returned by
        // `Box::into_raw`; PAM owns it only when `status` is SUCCESS.
        unsafe { finish_store::<PamSecretBytes>(status, data) }
    }

    unsafe fn get_secret<'a>(&'a self, key: &str) -> PamResult<&'a PamSecretBytes> {
        let key = CString::new(key)?;
        let mut data: *const c_void = ptr::null();
        // SAFETY: `self.0` is the live PAM handle, `key` is a valid C string,
        // and `data` points to writable output storage for the duration of the
        // synchronous call.
        let status = PamError::new(unsafe { ffi::pam_get_data(self.0, key.as_ptr(), &mut data) });
        // SAFETY: the caller guarantees that a successful, non-null result for
        // `key` was registered by `send_secret` and remains live for `'a`.
        unsafe { secret_from_data(status, data) }
    }

    fn syslog(&self, lvl: LogLvl, msg: &str) -> PamResult<()> {
        let fmt = c"%s".as_ptr();
        let cmsg = CString::new(msg)?;
        // SAFETY: `self.0` is the live PAM handle; `fmt` expects one C string;
        // and `cmsg` remains allocated for the synchronous call.
        unsafe {
            ffi::pam_syslog(self.0, lvl as c_int, fmt, cmsg.as_ptr());
        }
        Ok(())
    }
}

/// Convert a `pam_set_data` result into the final ownership state.
///
/// # Safety
///
/// `data` must be the unique pointer returned by `Box::into_raw` for one live
/// `T`. On success PAM must have accepted ownership; on error PAM must not
/// retain or clean the pointer.
unsafe fn finish_store<T>(status: PamError, data: *mut c_void) -> PamResult<()> {
    if status == PamError::SUCCESS {
        Ok(())
    } else {
        // SAFETY: the caller guarantees PAM did not accept ownership on error,
        // so this remains the unique live pointer for one boxed `T`.
        unsafe { cleanup_boxed::<T>(data, status as c_int) };
        Err(status)
    }
}

/// Convert a checked `pam_get_data` output into a secret borrow.
///
/// # Safety
///
/// For a successful non-null result, `data` must point to a live
/// `PamSecretBytes` that remains immutable for `'a`.
unsafe fn secret_from_data<'a>(
    status: PamError,
    data: *const c_void,
) -> PamResult<&'a PamSecretBytes> {
    // SAFETY: the caller guarantees a successful non-null output names one
    // live, immutable `PamSecretBytes` for the returned lifetime.
    unsafe { required_data::<PamSecretBytes>(status as c_int, data) }
}

unsafe extern "C" fn pam_secret_cleanup(
    _handle: PamHandle,
    data: *mut c_void,
    error_status: c_int,
) {
    // SAFETY: Linux-PAM calls the registered cleanup at most once with the
    // exact boxed `PamSecretBytes` pointer accepted by `pam_set_data`; null is
    // handled defensively by `cleanup_boxed`.
    unsafe { cleanup_boxed::<PamSecretBytes>(data, error_status) };
}

const PAM_STATUS_MASK: c_int = 0xff;

/// Run a `PamData` observer and release its allocation without unwinding.
///
/// # Safety
///
/// When non-null, `data` must be the unique pointer returned by
/// `Box::into_raw` for one live `T`, and this function must be called exactly
/// once for that pointer. `handle` must satisfy the observer's own PAM usage.
unsafe fn cleanup_pam_data<T: PamData>(handle: PamHandle, data: *mut c_void, error_status: c_int) {
    if data.is_null() {
        return;
    }

    contain_cleanup(|| {
        // SAFETY: the caller guarantees `data` is the unique pointer for one
        // live boxed `T` and that this cleanup occurs exactly once.
        let data = unsafe { Box::from_raw(data as *mut T) };
        data.cleanup(
            Pam::from_handle(handle),
            PamFlags::from_bits_retain(error_status & !PAM_STATUS_MASK),
            PamError::new(error_status & PAM_STATUS_MASK),
        );
    });
}

unsafe extern "C" fn pam_data_cleanup<T: PamData>(
    handle: PamHandle,
    data: *mut c_void,
    error_status: c_int,
) {
    // SAFETY: Linux-PAM calls the registered cleanup at most once with the
    // exact boxed `T` pointer accepted by `pam_set_data`; null is handled
    // defensively by `cleanup_pam_data`.
    unsafe { cleanup_pam_data::<T>(handle, data, error_status) };
}

mod ffi {
    use super::{c_char, c_int, c_void, PamConstHandle, PamHandle};

    #[link(name = "pam")]
    // SAFETY: these declarations were compared with Linux-PAM 1.7.2's
    // installed pam_modules.h, pam_ext.h, and _pam_types.h using bindgen 0.72.1.
    unsafe extern "C" {
        pub(super) fn pam_set_item(pamh: PamHandle, item_type: c_int, item: *const c_void)
            -> c_int;
        pub(super) fn pam_get_item(
            pamh: PamConstHandle,
            item_type: c_int,
            item: *mut *const c_void,
        ) -> c_int;
        pub(super) fn pam_putenv(pamh: PamHandle, name_value: *const c_char) -> c_int;
        pub(super) fn pam_getenv(pamh: PamHandle, name: *const c_char) -> *const c_char;

        pub(super) fn pam_set_data(
            pamh: PamHandle,
            module_data_name: *const c_char,
            data: *mut c_void,
            cleanup: Option<unsafe extern "C" fn(PamHandle, *mut c_void, c_int)>,
        ) -> c_int;
        pub(super) fn pam_get_data(
            pamh: PamConstHandle,
            module_data_name: *const c_char,
            data: *mut *const c_void,
        ) -> c_int;
        pub(super) fn pam_get_user(
            pamh: PamHandle,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
        pub(super) fn pam_get_authtok(
            pamh: PamHandle,
            item: c_int,
            authtok: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
        pub(super) fn pam_prompt(
            pamh: PamHandle,
            style: c_int,
            response: *mut *mut c_char,
            format: *const c_char,
            ...
        ) -> c_int;

        pub(super) fn pam_syslog(pamh: PamConstHandle, priority: c_int, format: *const c_char, ...);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PamSecretBytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    static FFI_VALUE: &[u8] = b"ffi-value\0";

    fn dangling_void() -> *const c_void {
        ptr::NonNull::<u8>::dangling().as_ptr() as *const c_void
    }

    fn dangling_char() -> *const c_char {
        ptr::NonNull::<u8>::dangling().as_ptr() as *const c_char
    }

    unsafe extern "C" fn get_item_error(
        _handle: PamConstHandle,
        _item_type: c_int,
        output: *mut *const c_void,
    ) -> c_int {
        // SAFETY: the test wrapper supplies writable output storage.
        unsafe { *output = dangling_void() };
        PamError::AUTH_ERR as c_int
    }

    unsafe extern "C" fn get_item_null(
        _handle: PamConstHandle,
        _item_type: c_int,
        output: *mut *const c_void,
    ) -> c_int {
        // SAFETY: the test wrapper supplies writable output storage.
        unsafe { *output = ptr::null() };
        PamError::SUCCESS as c_int
    }

    unsafe extern "C" fn get_item_value(
        _handle: PamConstHandle,
        _item_type: c_int,
        output: *mut *const c_void,
    ) -> c_int {
        // SAFETY: the test wrapper supplies writable output storage, and the
        // static C string outlives the returned borrow.
        unsafe { *output = FFI_VALUE.as_ptr() as *const c_void };
        PamError::SUCCESS as c_int
    }

    unsafe extern "C" fn get_char_error(
        _handle: PamHandle,
        output: *mut *const c_char,
        _prompt: *const c_char,
    ) -> c_int {
        // SAFETY: the test wrapper supplies writable output storage.
        unsafe { *output = dangling_char() };
        PamError::AUTH_ERR as c_int
    }

    unsafe extern "C" fn get_char_null(
        _handle: PamHandle,
        output: *mut *const c_char,
        _prompt: *const c_char,
    ) -> c_int {
        // SAFETY: the test wrapper supplies writable output storage.
        unsafe { *output = ptr::null() };
        PamError::SUCCESS as c_int
    }

    unsafe extern "C" fn get_char_value(
        _handle: PamHandle,
        output: *mut *const c_char,
        _prompt: *const c_char,
    ) -> c_int {
        // SAFETY: the test wrapper supplies writable output storage, and the
        // static C string outlives the returned borrow.
        unsafe { *output = FFI_VALUE.as_ptr() as *const c_char };
        PamError::SUCCESS as c_int
    }

    unsafe extern "C" fn get_authtok_error(
        handle: PamHandle,
        _item_type: c_int,
        output: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int {
        // SAFETY: this test stub has the same output contract as
        // `get_char_error` and forwards the wrapper-provided pointers.
        unsafe { get_char_error(handle, output, prompt) }
    }

    unsafe extern "C" fn get_authtok_null(
        handle: PamHandle,
        _item_type: c_int,
        output: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int {
        // SAFETY: this test stub has the same output contract as
        // `get_char_null` and forwards the wrapper-provided pointers.
        unsafe { get_char_null(handle, output, prompt) }
    }

    unsafe extern "C" fn get_authtok_value(
        handle: PamHandle,
        _item_type: c_int,
        output: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int {
        // SAFETY: this test stub has the same output contract as
        // `get_char_value` and forwards the wrapper-provided pointers.
        unsafe { get_char_value(handle, output, prompt) }
    }

    unsafe extern "C" fn set_item_success(
        _handle: PamHandle,
        _item_type: c_int,
        _item: *const c_void,
    ) -> c_int {
        PamError::SUCCESS as c_int
    }

    unsafe extern "C" fn set_item_error(
        _handle: PamHandle,
        _item_type: c_int,
        _item: *const c_void,
    ) -> c_int {
        PamError::BAD_ITEM as c_int
    }

    unsafe extern "C" fn putenv_success(_handle: PamHandle, _name_value: *const c_char) -> c_int {
        PamError::SUCCESS as c_int
    }

    unsafe extern "C" fn putenv_error(_handle: PamHandle, _name_value: *const c_char) -> c_int {
        PamError::BAD_ITEM as c_int
    }

    unsafe fn prompt_success(_handle: PamHandle, _message: *const c_char) -> c_int {
        PamError::SUCCESS as c_int
    }

    unsafe fn prompt_error(_handle: PamHandle, _message: *const c_char) -> c_int {
        PamError::CONV_ERR as c_int
    }

    const ERROR_API: PamApi = PamApi {
        get_item: get_item_error,
        get_user: get_char_error,
        get_authtok: get_authtok_error,
        set_item: set_item_error,
        putenv: putenv_error,
    };

    const NULL_API: PamApi = PamApi {
        get_item: get_item_null,
        get_user: get_char_null,
        get_authtok: get_authtok_null,
        set_item: set_item_success,
        putenv: putenv_success,
    };

    const VALUE_API: PamApi = PamApi {
        get_item: get_item_value,
        get_user: get_char_value,
        get_authtok: get_authtok_value,
        set_item: set_item_success,
        putenv: putenv_success,
    };

    #[test]
    fn ffi_contract_checks_status_before_output_and_rejects_required_nulls() {
        let handle = ptr::NonNull::<u8>::dangling().as_ptr() as PamHandle;

        // SAFETY: the injected stubs never dereference `handle`; their output
        // pointers remain valid for each synchronous call.
        unsafe {
            assert!(matches!(
                get_item_with(&ERROR_API, handle, PamItemType::USER),
                Err(PamError::AUTH_ERR)
            ));
            assert!(matches!(
                get_user_with(&ERROR_API, handle, ptr::null()),
                Err(PamError::AUTH_ERR)
            ));
            assert!(matches!(
                get_authtok_with(&ERROR_API, handle, PamItemType::AUTHTOK, ptr::null()),
                Err(PamError::AUTH_ERR)
            ));

            assert!(matches!(
                get_item_with(&NULL_API, handle, PamItemType::USER),
                Ok(None)
            ));
            assert!(matches!(
                get_user_with(&NULL_API, handle, ptr::null()),
                Err(PamError::SYSTEM_ERR)
            ));
            assert!(matches!(
                get_authtok_with(&NULL_API, handle, PamItemType::AUTHTOK, ptr::null()),
                Err(PamError::SYSTEM_ERR)
            ));

            assert!(matches!(
                set_item_with(&ERROR_API, handle, PamItemType::AUTHTOK, ptr::null()),
                Err(PamError::BAD_ITEM)
            ));
            assert!(matches!(
                putenv_with(&ERROR_API, handle, FFI_VALUE.as_ptr() as *const c_char),
                Err(PamError::BAD_ITEM)
            ));
            assert!(matches!(
                info_with(prompt_error, handle, FFI_VALUE.as_ptr() as *const c_char),
                Err(PamError::CONV_ERR)
            ));

            let item = get_item_with(&VALUE_API, handle, PamItemType::USER)
                .expect("value status")
                .expect("value pointer");
            assert_eq!(item.to_bytes(), b"ffi-value");
            assert_eq!(
                get_user_with(&VALUE_API, handle, ptr::null())
                    .expect("user value")
                    .to_bytes(),
                b"ffi-value"
            );
            assert_eq!(
                get_authtok_with(&VALUE_API, handle, PamItemType::AUTHTOK, ptr::null(),)
                    .expect("token value")
                    .to_bytes(),
                b"ffi-value"
            );
            assert_eq!(
                set_item_with(&VALUE_API, handle, PamItemType::AUTHTOK, ptr::null()),
                Ok(())
            );
            assert_eq!(
                putenv_with(&VALUE_API, handle, FFI_VALUE.as_ptr() as *const c_char),
                Ok(())
            );
            assert_eq!(
                info_with(prompt_success, handle, FFI_VALUE.as_ptr() as *const c_char),
                Ok(())
            );
        }
    }

    #[test]
    fn ffi_contract_required_data_checks_status_before_pointer() {
        let invalid = dangling_void();

        // SAFETY: the error case must return before inspecting `invalid`, and
        // the null success case must return before dereference.
        unsafe {
            assert!(matches!(
                required_data::<u8>(PamError::NO_MODULE_DATA as c_int, invalid),
                Err(PamError::NO_MODULE_DATA)
            ));
            assert!(matches!(
                required_data::<u8>(PamError::SUCCESS as c_int, ptr::null()),
                Err(PamError::SYSTEM_ERR)
            ));
        }

        let value = 42_u8;
        // SAFETY: `value` remains live and immutable for the returned borrow.
        let borrowed = unsafe {
            required_data::<u8>(
                PamError::SUCCESS as c_int,
                &value as *const u8 as *const c_void,
            )
        }
        .expect("valid data output");
        assert_eq!(*borrowed, 42);
    }

    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PamDataProbe {
        cleanup_calls: Arc<AtomicUsize>,
        replacement_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        panic_payload_in_cleanup: bool,
    }

    impl PamData for PamDataProbe {
        fn cleanup(&self, _pam: Pam, flags: PamFlags, _status: PamError) {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            if flags.contains(PamFlags::DATA_REPLACE) {
                self.replacement_calls.fetch_add(1, Ordering::SeqCst);
            }
            if self.panic_payload_in_cleanup {
                struct PanicsOnDrop;

                impl Drop for PanicsOnDrop {
                    fn drop(&mut self) {
                        panic!("intentional cleanup panic-payload drop");
                    }
                }

                std::panic::resume_unwind(Box::new(PanicsOnDrop));
            }
        }
    }

    impl Drop for PamDataProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CleanupFlagProbe(Arc<AtomicUsize>);

    impl PamData for CleanupFlagProbe {
        fn cleanup(&self, _pam: Pam, flags: PamFlags, _status: PamError) {
            if flags.bits() & 0x4000_0000 != 0 {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct CleanupStatusProbe {
        saw_status: Arc<AtomicUsize>,
        saw_low_flag_bits: Arc<AtomicUsize>,
    }

    impl PamData for CleanupStatusProbe {
        fn cleanup(&self, _pam: Pam, flags: PamFlags, status: PamError) {
            if status == PamError::AUTH_ERR {
                self.saw_status.fetch_add(1, Ordering::SeqCst);
            }
            if flags.bits() & 0xff != 0 {
                self.saw_low_flag_bits.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn boxed_pam_data_probe(
        cleanup_calls: Arc<AtomicUsize>,
        replacement_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        panic_payload_in_cleanup: bool,
    ) -> *mut c_void {
        Box::into_raw(Box::new(PamDataProbe {
            cleanup_calls,
            replacement_calls,
            drops,
            panic_payload_in_cleanup,
        })) as *mut c_void
    }

    #[test]
    fn irlume_boundary_exposes_clear_and_response_free_info() {
        fn require_clear(pam: &Pam) -> PamResult<()> {
            pam.clear_authtok()
        }
        fn require_info(pam: &Pam) -> PamResult<()> {
            pam.info("Type yes to use face authentication")
        }

        let _: fn(&Pam) -> PamResult<()> = require_clear;
        let _: fn(&Pam) -> PamResult<()> = require_info;
    }

    #[test]
    fn secret_storage_api_has_owned_send_and_borrowed_get() {
        fn require_send(pam: &Pam, key: &str, value: PamSecretBytes) -> PamResult<()> {
            pam.send_secret(key, value)
        }
        unsafe fn require_get<'a>(pam: &'a Pam, key: &str) -> PamResult<&'a PamSecretBytes> {
            // SAFETY: this compile contract preserves the caller's documented
            // requirement that `key` names a live stored secret.
            unsafe { pam.get_secret(key) }
        }

        let _: fn(&Pam, &str, PamSecretBytes) -> PamResult<()> = require_send;
        let _ = require_get;
    }

    #[test]
    fn failed_storage_reclaims_transferred_ownership_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let data = Box::into_raw(Box::new(DropProbe(Arc::clone(&drops)))) as *mut c_void;

        // SAFETY: `data` is one live `DropProbe` allocation transferred to
        // this ownership-result seam exactly once.
        let result = unsafe { finish_store::<DropProbe>(PamError::SYSTEM_ERR, data) };

        assert_eq!(result, Err(PamError::SYSTEM_ERR));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn successful_storage_leaves_ownership_with_pam() {
        let drops = Arc::new(AtomicUsize::new(0));
        let data = Box::into_raw(Box::new(DropProbe(Arc::clone(&drops)))) as *mut c_void;

        // SAFETY: `data` is one live `DropProbe`; success transfers ownership
        // to PAM, then the test invokes its cleanup exactly once.
        let result = unsafe { finish_store::<DropProbe>(PamError::SUCCESS, data) };
        assert_eq!(result, Ok(()));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        unsafe { crate::module_data::cleanup_boxed::<DropProbe>(data, 0) };
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn secret_lookup_checks_status_and_null_before_borrowing() {
        let invalid = ptr::NonNull::<u8>::dangling().as_ptr() as *const c_void;

        // SAFETY: an error status must return before inspecting `invalid`.
        let error = unsafe { secret_from_data(PamError::NO_MODULE_DATA, invalid) };
        assert!(matches!(error, Err(PamError::NO_MODULE_DATA)));

        // SAFETY: a null success output must be rejected before dereference.
        let missing = unsafe { secret_from_data(PamError::SUCCESS, ptr::null()) };
        assert!(matches!(missing, Err(PamError::SYSTEM_ERR)));

        let secret = Box::new(PamSecretBytes::new(b"fixed-ci-dummy".to_vec()));
        // SAFETY: the pointer names `secret`, which remains live and immutable
        // for the duration of the returned borrow.
        let borrowed = unsafe {
            secret_from_data(
                PamError::SUCCESS,
                &*secret as *const PamSecretBytes as *const c_void,
            )
        }
        .expect("valid secret pointer");
        assert!(borrowed.expose() == b"fixed-ci-dummy");
    }

    #[test]
    fn pam_data_cleanup_observes_end_and_replacement_then_drops_once() {
        let cleanup_calls = Arc::new(AtomicUsize::new(0));
        let replacement_calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));

        for status in [0, PamFlags::DATA_REPLACE.bits()] {
            let data = boxed_pam_data_probe(
                Arc::clone(&cleanup_calls),
                Arc::clone(&replacement_calls),
                Arc::clone(&drops),
                false,
            );
            // SAFETY: each pointer names one live `PamDataProbe`, is passed
            // exactly once, and the observer never reads the null PAM handle.
            unsafe { cleanup_pam_data::<PamDataProbe>(ptr::null_mut(), data, status) };
        }

        assert_eq!(cleanup_calls.load(Ordering::SeqCst), 2);
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pam_data_cleanup_ignores_null_and_contains_observer_panics() {
        // SAFETY: null data is explicitly supported as a defensive no-op.
        unsafe { cleanup_pam_data::<PamDataProbe>(ptr::null_mut(), ptr::null_mut(), 0) };

        let cleanup_calls = Arc::new(AtomicUsize::new(0));
        let replacement_calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let data = boxed_pam_data_probe(
            Arc::clone(&cleanup_calls),
            Arc::clone(&replacement_calls),
            Arc::clone(&drops),
            true,
        );

        // SAFETY: `data` names one live `PamDataProbe`, is passed exactly
        // once, and the observer never reads the null PAM handle.
        unsafe { cleanup_pam_data::<PamDataProbe>(ptr::null_mut(), data, 0) };

        assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pam_data_cleanup_retains_the_data_silent_flag() {
        let observed = Arc::new(AtomicUsize::new(0));
        let data = Box::into_raw(Box::new(CleanupFlagProbe(Arc::clone(&observed)))) as *mut c_void;

        // SAFETY: `data` names one live `CleanupFlagProbe`, is passed exactly
        // once, and the observer never reads the null PAM handle.
        unsafe { cleanup_pam_data::<CleanupFlagProbe>(ptr::null_mut(), data, 0x4000_0000) };

        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pam_data_cleanup_separates_status_from_flag_bits() {
        let saw_status = Arc::new(AtomicUsize::new(0));
        let saw_low_flag_bits = Arc::new(AtomicUsize::new(0));
        let data = Box::into_raw(Box::new(CleanupStatusProbe {
            saw_status: Arc::clone(&saw_status),
            saw_low_flag_bits: Arc::clone(&saw_low_flag_bits),
        })) as *mut c_void;

        // SAFETY: `data` names one live `CleanupStatusProbe`, is passed exactly
        // once, and the observer never reads the null PAM handle.
        unsafe {
            cleanup_pam_data::<CleanupStatusProbe>(
                ptr::null_mut(),
                data,
                PamError::AUTH_ERR as c_int,
            )
        };

        assert_eq!(saw_status.load(Ordering::SeqCst), 1);
        assert_eq!(saw_low_flag_bits.load(Ordering::SeqCst), 0);
    }
}
