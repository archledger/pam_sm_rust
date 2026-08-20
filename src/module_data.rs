use std::fmt;
#[cfg(any(feature = "libpam", test))]
use std::os::raw::{c_int, c_void};
use zeroize::Zeroize;

/// Owned secret bytes that are zeroized before their allocation is released.
pub struct PamSecretBytes(Vec<u8>);

impl PamSecretBytes {
    /// Wrap secret bytes for storage in a PAM transaction.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the secret contents explicitly.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Return the secret length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for PamSecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PamSecretBytes([redacted; {} bytes])", self.len())
    }
}

impl Drop for PamSecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(crate) fn wipe(bytes: &mut Vec<u8>) {
    bytes.zeroize();
}

/// Drop one value previously transferred with `Box::into_raw`.
///
/// # Safety
///
/// When non-null, `data` must have been returned by `Box::into_raw` for one
/// live `T`, and this function must be called exactly once for that pointer.
#[cfg(any(feature = "libpam", test))]
pub(crate) unsafe fn cleanup_boxed<T>(data: *mut c_void, _error_status: c_int) {
    if data.is_null() {
        return;
    }

    contain_cleanup(|| {
        // SAFETY: the caller guarantees that `data` is the unique raw pointer
        // for one live boxed `T` and that cleanup occurs exactly once.
        drop(unsafe { Box::from_raw(data as *mut T) });
    });
}

#[cfg(any(feature = "libpam", test))]
pub(crate) fn contain_cleanup<F>(cleanup: F)
where
    F: FnOnce(),
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup));
    if let Err(payload) = result {
        if let Err(nested_payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
        {
            std::mem::forget(nested_payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct DropProbe {
        _secret: PamSecretBytes,
        drops: Arc<AtomicUsize>,
        panic_payload_on_drop: bool,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.panic_payload_on_drop {
                struct PanicsOnDrop;

                impl Drop for PanicsOnDrop {
                    fn drop(&mut self) {
                        panic!("intentional panic-payload drop");
                    }
                }

                std::panic::resume_unwind(Box::new(PanicsOnDrop));
            }
        }
    }

    fn boxed_probe(drops: Arc<AtomicUsize>, panic_payload_on_drop: bool) -> *mut c_void {
        Box::into_raw(Box::new(DropProbe {
            _secret: PamSecretBytes::new(b"fixed-ci-dummy".to_vec()),
            drops,
            panic_payload_on_drop,
        })) as *mut c_void
    }

    #[test]
    fn secret_exposure_is_explicit_and_debug_is_redacted() {
        let secret = PamSecretBytes::new(b"fixed-ci-dummy".to_vec());

        assert!(secret.expose() == b"fixed-ci-dummy");
        assert_eq!(secret.len(), 14);
        assert!(!secret.is_empty());
        assert_eq!(
            format!("{secret:?}"),
            "PamSecretBytes([redacted; 14 bytes])"
        );
    }

    #[test]
    fn empty_secret_reports_empty() {
        let secret = PamSecretBytes::new(Vec::new());

        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn secret_memory_is_wiped() {
        let mut bytes = b"fixed-ci-dummy".to_vec();

        wipe(&mut bytes);

        assert!(bytes.is_empty());
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn normal_and_replacement_cleanup_each_drop_once() {
        let drops = Arc::new(AtomicUsize::new(0));

        for status in [0, crate::PamFlags::DATA_REPLACE.bits()] {
            let data = boxed_probe(Arc::clone(&drops), false);
            // SAFETY: `data` came from `Box::into_raw` for exactly one
            // `DropProbe`, and each pointer is passed to cleanup once.
            unsafe { cleanup_boxed::<DropProbe>(data, status) };
        }

        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cleanup_ignores_a_null_data_pointer() {
        // SAFETY: null is explicitly supported as a defensive no-op.
        unsafe { cleanup_boxed::<DropProbe>(ptr::null_mut(), 0) };
    }

    #[test]
    fn cleanup_contains_panics_from_drop_and_the_panic_payload() {
        let drops = Arc::new(AtomicUsize::new(0));
        let data = boxed_probe(Arc::clone(&drops), true);

        // SAFETY: `data` came from `Box::into_raw` for exactly one
        // `DropProbe` and is passed to cleanup once.
        unsafe { cleanup_boxed::<DropProbe>(data, 0) };

        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
