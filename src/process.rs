use crate::operations::{Action, Product};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub struct ExecutionResult {
    pub output: String,
}

#[cfg(windows)]
pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}
#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}

pub fn execute(
    product: Product,
    action: Action,
    cancel: Arc<AtomicBool>,
) -> Result<ExecutionResult, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("操作已取消".into());
    }
    #[cfg(windows)]
    let result = crate::native::licensing::execute(product, &action, &|_| {});
    #[cfg(not(windows))]
    let result: Result<String, String> = {
        let _ = product;
        Err(crate::operations::ValidationError::UnsupportedPlatform.to_string())
    };
    let redact = |mut text: String| {
        for secret in action.secrets() {
            text = text.replace(secret, "*****");
        }
        text
    };
    result
        .map(|output| ExecutionResult {
            output: redact(output),
        })
        .map_err(redact)
}
