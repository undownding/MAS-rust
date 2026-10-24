//! TSforge codecs ported from the pinned MAS LibTSforge source (GPL-3.0-only).
//! Reset is native; activation and token modification routes are still being migrated.
mod binary;
mod crypto;
mod physical;
mod reset;
mod service;
#[cfg(windows)]
mod sl;
#[cfg(test)]
mod token;
mod transaction;
#[cfg(test)]
mod variable_bag;

#[cfg(windows)]
mod runtime;
#[cfg(windows)]
pub use runtime::{reset, restore};

// Product-key installation/configuration integration is still in progress.
#[cfg(test)]
mod key_install;
#[cfg(test)]
mod legacy_random;
#[cfg(test)]
mod pkey_config;
#[cfg(test)]
mod product_key;

#[cfg(windows)]
mod registry_backup;
