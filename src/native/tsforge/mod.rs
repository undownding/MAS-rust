//! TSforge codecs ported from the pinned MAS LibTSforge source (GPL-3.0-only).
//! Staged under tests until authenticated storage and transactional writes exist.
mod binary;
mod crypto;
mod physical;
#[cfg(windows)]
mod sl;
mod token;
mod variable_bag;
