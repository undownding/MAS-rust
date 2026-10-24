//! Native migration: shared licensing, HWID and legacy KMS38.
#[cfg(windows)]
mod activation;
#[cfg(any(windows, test))]
pub mod catalog;
#[cfg(windows)]
pub mod licensing;
#[cfg(windows)]
mod platform;
#[cfg(any(windows, test))]
pub mod ticket;
#[cfg(windows)]
pub use activation::run;

#[cfg(any(windows, test))]
pub mod kms;
#[cfg(windows)]
pub mod online;
#[cfg(windows)]
pub mod renewal;

#[cfg(windows)]
mod office;
#[cfg(any(windows, test))]
mod office_catalog;
#[cfg(windows)]
mod registry;

#[cfg(any(windows, test))]
mod hook_files;
#[cfg(windows)]
mod office_cleanup;
#[cfg(windows)]
pub mod ohook;

#[cfg(windows)]
pub mod session;

#[cfg(test)]
#[path = "../../vendor/ohook-rs/src/policy.rs"]
mod hook_policy;
#[cfg(test)]
#[path = "../../build_support/pe.rs"]
mod pe_tests;

#[cfg(any(windows, test))]
pub mod tsforge;

#[cfg(any(windows, test))]
pub mod office_repair;

pub mod system_repair;

#[cfg(any(windows, test))]
mod cabinet;

#[cfg(any(windows, test))]
pub mod wmi_repair;

#[cfg(any(windows, test))]
mod wmi_repository;
