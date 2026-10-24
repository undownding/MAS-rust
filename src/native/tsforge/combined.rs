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
pub fn method(option: usize, build: u32) -> Result<Method, String> {
    super::crypto::Version::detect(build).map_err(|e| e.to_string())?;
    let method = match option {
        0 if build >= 26100 => Method::StaticCid,
        0 | 2 => Method::ZeroCid,
        1 => Method::StaticCid,
        3 => Method::Kms4k,
        _ => return Err("未知 TSforge 方法".into()),
    };
    if method == Method::StaticCid && build < 9200 {
        return Err("StaticCID 需要 Windows 8 或更高版本，未执行组合修改。".into());
    }
    Ok(method)
}
pub fn run(
    build: u32,
    selected: Method,
    cleanup: impl FnOnce() -> Result<(), String>,
    mut activate: impl FnMut(Scope, Method) -> Result<Option<String>, String>,
) -> Result<String, String> {
    let method = method(selected.option(), build)?;
    cleanup().map_err(|e| format!("组合流程共享准备失败，未继续激活：{e}"))?;
    let mut messages = Vec::new();
    let mut failed = false;
    for scope in [Scope::Windows, Scope::Esu, Scope::Office] {
        if scope == Scope::Office && build < 9200 {
            messages.push("Office：跳过，TSforge Office 仅支持 Windows 8 及更高版本。".into());
            continue;
        }
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
    runtime::storage_preflight()?;
    let method = connectivity::resolve(method(option, context.build)?, option == 0, || {
        connectivity::connected(report)
    })?;
    report(&format!("原生 Windows + ESU + Office：共享方法 {method:?}"));
    let result = run(
        context.build,
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
    fn legacy_combination_skips_unsupported_scopes_without_calling_them() {
        for build in [6000, 6002, 7600, 7601] {
            assert_eq!(method(0, build).unwrap(), Method::ZeroCid);
            for selected in [Method::ZeroCid, Method::Kms4k] {
                let mut calls = vec![];
                let mut cleaned = 0;
                let message = run(
                    build,
                    selected,
                    || {
                        cleaned += 1;
                        Ok(())
                    },
                    |scope, method| {
                        assert_eq!(method, selected);
                        calls.push(scope);
                        Ok(Some("verified".into()))
                    },
                )
                .unwrap();
                assert_eq!(cleaned, 1);
                assert_eq!(
                    calls,
                    if selected == Method::Kms4k {
                        vec![Scope::Windows]
                    } else {
                        vec![Scope::Windows, Scope::Esu]
                    }
                );
                assert!(message.contains("Office：跳过"));
            }
            assert!(
                run(
                    build,
                    Method::StaticCid,
                    || panic!("must not clean"),
                    |_, _| panic!("must not activate")
                )
                .is_err()
            );
        }
        assert!(
            run(
                7603,
                Method::ZeroCid,
                || panic!("unknown build"),
                |_, _| panic!()
            )
            .is_err()
        );
    }
    #[test]
    fn same_resolved_method_reaches_each_scope_and_kms_skips_esu() {
        for method in [Method::StaticCid, Method::ZeroCid, Method::Kms4k] {
            let mut calls = Vec::new();
            let result = run(
                26100,
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
            26100,
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
                26100,
                Method::Kms4k,
                || Err("cleanup failed".into()),
                |_, _| panic!("must not activate")
            )
            .unwrap_err()
            .contains("cleanup failed")
        );
    }
    #[test]
    fn method_option_roundtrips_and_combined_auto_policy() {
        for method in [Method::StaticCid, Method::ZeroCid, Method::Kms4k] {
            assert_eq!(self::method(method.option(), 26100).unwrap(), method);
        }
        assert_eq!(self::method(0, 26100).unwrap(), Method::StaticCid);
        assert_eq!(self::method(0, 26099).unwrap(), Method::ZeroCid);
    }
}
