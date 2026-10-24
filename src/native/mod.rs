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
