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
