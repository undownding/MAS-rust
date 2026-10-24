//! Windows + ESU + Office orchestration with one method and shared cleanup.
#![cfg_attr(not(test), allow(dead_code))]
use super::activation_flow::Method;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Windows,
    Esu,
    Office,
}
impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Esu => "ESU",
            Self::Office => "Office",
        }
    }
}
pub fn run(
    method: Method,
    cleanup: impl FnOnce() -> Result<(), String>,
    mut activate: impl FnMut(Scope, Method) -> Result<Option<String>, String>,
) -> Result<String, String> {
    cleanup().map_err(|e| format!("组合流程共享准备失败，未继续激活：{e}"))?;
    let mut messages = Vec::new();
    let mut failed = false;
    for scope in [Scope::Windows, Scope::Esu, Scope::Office] {
        if scope == Scope::Esu && method == Method::Kms4k {
            messages.push("ESU：跳过，KMS4k 不支持 ESU；可联网后选择 Auto 或 StaticCID".into());
            continue;
        }
        let outcome = match activate(scope, method) {
            Ok(Some(message)) => message,
            Ok(None) => {
                failed = true;
                "系统状态已变化，返回兼容请求；前序操作可能已修改许可，因此未自动运行脚本".into()
            }
            Err(error) => {
                failed = true;
                format!("失败：{error}")
            }
        };
        messages.push(format!("{}：{outcome}", scope.name()));
    }
    if failed {
        Err(format!(
            "组合处理存在失败，已完成修改不自动回滚：\n{}",
            messages.join("\n")
        ))
    } else {
        Ok(format!(
            "组合处理结束（各范围结果如下）：\n{}",
            messages.join("\n")
        ))
    }
}
#[cfg(windows)]
pub fn activate(option: usize, report: &dyn Fn(&str)) -> Result<Option<String>, String> {
    use super::{
        connectivity, esu_runtime, kms_cleanup, office_client, reevaluation, runtime,
        windows_context,
    };
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
        return Err("原生 TSforge 不支持跨架构仿真，请使用本机 x64 构建".into());
    }
    let context = windows_context::Context::read(report)?;
    // Decide whole-request compatibility before ANY component can mutate state.
    if context.build < 9600 || context.edition.to_ascii_lowercase().contains("eval") {
        return Ok(None);
    }
    runtime::preflight()?;
    let method = connectivity::resolve(
        office_client::method(option, context.build)?,
        option == 0,
        || connectivity::connected(report),
    )?;
    report(&format!("原生 Windows + ESU + Office：共享方法 {method:?}"));
    let result = run(
        method,
        || {
            if method == Method::Kms4k {
                kms_cleanup::clear(context.build, report)?;
            }
            Ok(())
        },
        |scope, method| {
            report(&format!("开始处理 {}", scope.name()));
            match scope {
                Scope::Windows => windows_context::activate_combined(method, report),
                Scope::Esu => esu_runtime::activate_combined(method, report),
                Scope::Office => office_client::activate_combined(method, report),
            }
        },
    );
    reevaluation::finish(result, || reevaluation::run(context.build, report)).map(Some)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_resolved_method_reaches_each_scope_and_kms_skips_esu() {
        for method in [Method::StaticCid, Method::ZeroCid, Method::Kms4k] {
            let mut calls = Vec::new();
            let result = run(
                method,
                || Ok(()),
                |scope, selected| {
                    calls.push(scope);
                    assert_eq!(selected, method);
                    Ok(Some("verified or not applicable".into()))
                },
            )
            .unwrap();
            assert_eq!(
                calls,
                if method == Method::Kms4k {
                    vec![Scope::Windows, Scope::Office]
                } else {
                    vec![Scope::Windows, Scope::Esu, Scope::Office]
                }
            );
            assert_eq!(result.contains("跳过"), method == Method::Kms4k);
        }
    }
    #[test]
    fn failures_and_unexpected_fallback_do_not_repeat_or_stop_other_scopes() {
        let mut calls = Vec::new();
        let error = run(
            Method::StaticCid,
            || Ok(()),
            |scope, _| {
                calls.push(scope);
                match scope {
                    Scope::Windows => Err("key install failed; backup retained".into()),
                    Scope::Esu => Ok(None),
                    Scope::Office => Ok(Some("Office verified".into())),
                }
            },
        )
        .unwrap_err();
        assert_eq!(calls, [Scope::Windows, Scope::Esu, Scope::Office]);
        assert!(
            error.contains("backup retained")
                && error.contains("未自动运行脚本")
                && error.contains("Office verified")
        );
        assert!(
            run(
                Method::Kms4k,
                || Err("cleanup failed".into()),
                |_, _| panic!("must not activate")
            )
            .unwrap_err()
            .contains("cleanup failed")
        );
    }
    #[test]
    fn method_option_roundtrips_and_combined_auto_uses_office_policy() {
        for method in [Method::StaticCid, Method::ZeroCid, Method::Kms4k] {
            assert_eq!(
                super::super::office_client::method(method.option(), 26100).unwrap(),
                method
            );
        }
        assert_eq!(
            super::super::office_client::method(0, 26100).unwrap(),
            Method::StaticCid
        );
        assert_eq!(
            super::super::office_client::method(0, 26099).unwrap(),
            Method::ZeroCid
        );
    }
}
