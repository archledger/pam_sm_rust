// Copyright (C) 2016 Raphael Catolino

#![deny(improper_ctypes)]
#![deny(improper_ctypes_definitions)]
#![deny(unsafe_op_in_unsafe_fn)]

//! PAM Service Module wrappers
//! # Usage
//! For example, here is a module that only authenticates when invoked with
//! the `allow` argument :
//!
//! ```rust,no_run
//! #[macro_use] extern crate pamsm;
//!
//! use pamsm::{PamServiceModule, Pam, PamFlags, PamError};
//!
//! struct PamArg;
//!
//! impl PamServiceModule for PamArg {
//!     fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
//!         if args.iter().any(|a| a == "allow") {
//!             PamError::SUCCESS
//!         } else {
//!             PamError::AUTH_ERR
//!         }
//!     }
//! }
//!
//! pam_module!(PamArg);
//! ```
#[macro_use]
extern crate bitflags;
extern crate zeroize;

#[doc(hidden)]
pub mod entrypoint;
#[cfg(feature = "libpam")]
mod libpam;
mod module_data;
mod pam;
mod pam_types;

pub use module_data::PamSecretBytes;
pub use pam::{Pam, PamError, PamFlags, PamServiceModule};

#[cfg(feature = "libpam")]
pub use libpam::{PamData, PamLibExt, PamResult};
#[cfg(feature = "libpam")]
pub use pam_types::{LogLvl, PamMsgStyle};
