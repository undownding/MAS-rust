//! TSforge codecs ported from the pinned MAS LibTSforge source (GPL-3.0-only).
//! Reset is native; activation and token modification routes are still being migrated.
mod binary;
mod crypto;
mod physical;
mod reset;
mod service;
#[cfg(windows)]
mod sl;
#[cfg_attr(not(test), allow(dead_code))]
mod token;
mod transaction;
#[cfg_attr(not(test), allow(dead_code))]
mod variable_bag;

#[cfg(windows)]
mod runtime;
#[cfg(windows)]
pub use runtime::{reset, restore};

// Product-key installation/configuration integration is still in progress.
#[cfg_attr(not(test), allow(dead_code))]
mod key_install;
#[cfg_attr(not(test), allow(dead_code))]
mod legacy_random;
#[cfg_attr(not(test), allow(dead_code))]
mod pkey_config;
#[cfg_attr(not(test), allow(dead_code))]
mod product_key;

#[cfg(windows)]
mod registry_backup;

mod registry_targets;

mod generated_key;

#[cfg(windows)]
mod key_runtime;
mod pid_context;

mod phone;

#[cfg(windows)]
mod phone_runtime;

mod activation_ws;

#[cfg(windows)]
mod activation_http;

#[cfg(windows)]
mod static_cid;

mod kms4k;

#[cfg(windows)]
mod kms4k_runtime;

mod host_charge;

#[cfg(windows)]
mod host_runtime;

mod product_selection;
#[cfg(windows)]
mod selection_runtime;

mod activation_flow;
mod connectivity;
mod esu;
#[cfg(windows)]
mod esu_runtime;
#[cfg(windows)]
pub use esu_runtime::activate as activate_esu;
mod host_licenses;
mod kms_cleanup;
mod reevaluation;
#[cfg(windows)]
mod windows_context;
#[cfg(windows)]
mod windows_host;
#[cfg(windows)]
pub use windows_context::activate as activate_windows;
#[cfg(windows)]
pub use windows_host::activate as activate_windows_host;
mod auxiliary;
#[cfg(windows)]
mod auxiliary_runtime;
#[cfg(windows)]
pub use auxiliary::Scope as AuxiliaryScope;
#[cfg(windows)]
pub use auxiliary_runtime::activate as activate_auxiliary;
mod license_reinstall;
mod office_client;
#[cfg(windows)]
pub use office_client::activate as activate_office;
mod office_finalization;
mod office_preparation;
#[cfg(windows)]
mod office_runtime;
mod office_selection;
mod office_uwp;
mod windows_edition;
