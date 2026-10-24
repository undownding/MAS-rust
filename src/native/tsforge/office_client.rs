//! Office / Project / Visio native activation orchestration.
#![cfg_attr(not(test), allow(dead_code))]
use super::activation_flow::Method;
use uuid::Uuid;
pub fn method(option: usize, build: u32) -> Result<Method, String> {
    match option {
        0 if build >= 26100 => Ok(Method::StaticCid),
        0 | 2 => Ok(Method::ZeroCid),
        1 => Ok(Method::StaticCid),
        3 => Ok(Method::Kms4k),
        _ => Err("未知 TSforge 方法".into()),
    }
}
pub fn batch(
    ids: &[Uuid],
    mut errors: Vec<String>,
    cleanup: impl FnOnce() -> Result<(), String>,
    mut activate: impl FnMut(Uuid) -> Result<(), String>,
) -> Result<String, String> {
    if ids.is_empty() {
        errors.insert(0, "没有可处理的 Office 激活 ID".into());
        return Err(errors.join("\n"));
    }
    if let Err(error) = cleanup() {
        errors.push(format!(
            "Office 激活前清理失败，未继续安装密钥；此前的配置/许可修改不自动撤销：{error}"
        ));
        return Err(errors.join("\n"));
    }
    let mut succeeded = 0;
    for id in ids {
        match activate(*id) {
            Ok(()) => succeeded += 1,
            Err(e) => errors.push(format!("{id}：{e}")),
        }
    }
    if errors.is_empty() {
        Ok(format!("Office 已验证 {succeeded} 项许可状态。"))
    } else {
        Err(format!(
            "Office 已验证 {succeeded}/{} 项；已完成修改不自动回滚：\n{}",
            ids.len(),
            errors.join("\n")
        ))
    }
}
#[cfg(windows)]
#[allow(dead_code)]
pub fn activate(
    project_visio_only: bool,
    option: usize,
    report: &dyn Fn(&str),
) -> Result<Option<String>, String> {
    use super::{
        activation_flow, connectivity, kms_cleanup, office_finalization, office_runtime,
        reevaluation, runtime, windows_context::Context,
    };
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    let context = Context::read(report)?;
    if context.build < 9200 {
        return Err("TSforge Office 需要 Windows 8 或更高版本".into());
    }
    if context.build < 9600 {
        return Ok(None);
    }
    runtime::preflight()?;
    let selected = connectivity::resolve(method(option, context.build)?, option == 0, || {
        connectivity::connected(report)
    })?;
    let prepared = office_runtime::prepare(context.build, selected, project_visio_only, report)?;
    let result = batch(
        &prepared.ids,
        prepared.errors.clone(),
        || {
            if selected == Method::Kms4k {
                kms_cleanup::clear(context.build, report)?;
            }
            office_finalization::finish(&prepared, project_visio_only, selected, report)
        },
        |id| {
            report(&format!("Office · {id} · {selected:?}"));
            let mut backend = activation_flow::Native {
                report,
                cleanup_build: None,
                required_channel: None,
            };
            match activation_flow::run(&mut backend, id, selected) {
                Ok(message) => {
                    report(&message);
                    Ok(())
                }
                Err(error) => {
                    report(&error);
                    Err(error)
                }
            }
        },
    );
    if prepared.ids.is_empty() {
        return result.map(Some);
    }
    reevaluation::finish(result, || reevaluation::run(context.build, report)).map(Some)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn office_auto_differs_from_windows_and_explicit_options_are_stable() {
        assert_eq!(method(0, 26099).unwrap(), Method::ZeroCid);
        assert_eq!(method(0, 26100).unwrap(), Method::StaticCid);
        for build in [9600, 26100] {
            assert_eq!(method(1, build).unwrap(), Method::StaticCid);
            assert_eq!(method(2, build).unwrap(), Method::ZeroCid);
            assert_eq!(method(3, build).unwrap(), Method::Kms4k);
        }
        assert!(method(4, 26100).is_err());
    }
    #[test]
    fn cleanup_failure_stops_activation_and_partial_failures_remain_visible() {
        let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
        let error = batch(
            &ids,
            vec!["preparation failed".into()],
            || Err("cache failed".into()),
            |_| panic!("must not activate"),
        )
        .unwrap_err();
        assert!(error.contains("preparation failed") && error.contains("cache failed"));
        let mut calls = Vec::new();
        let error = batch(
            &ids,
            vec!["preparation failed".into()],
            || Ok(()),
            |id| {
                calls.push(id);
                if id == ids[0] {
                    Err("activation failed".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(calls, ids);
        assert!(
            error.contains("1/2")
                && error.contains("preparation failed")
                && error.contains("activation failed")
        );
        assert!(batch(&[], vec![], || panic!("must not clean"), |_| panic!()).is_err());
        assert!(
            batch(&ids, vec![], || Ok(()), |_| Ok(()))
                .unwrap()
                .contains("2 项")
        );
    }
}
