//! Physical/token-store paths and service selection from pinned SPPUtils.
#![cfg_attr(not(test), allow(dead_code))]
use super::crypto::Version;
use std::path::{Path, PathBuf};
const PRIMARY: &str = "7B296FB0-376B-497e-B012-9C450E1B7327-0.C7483456-A289-439d-8115-601632D005A0";
const SECONDARY: &str =
    "7B296FB0-376B-497e-B012-9C450E1B7327-1.C7483456-A289-439d-8115-601632D005A0";
const FALLBACKS: [&str; 4] = [
    "spp/store",
    "spp/store/2.0",
    "spp/store_test",
    "spp/store_test/2.0",
];
pub struct Physical {
    pub version: Version,
    pub paths: Vec<PathBuf>,
    pub service: &'static str,
    pub missing_secondary: bool,
}
fn absolute(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("存储目录不是绝对路径：{}", path.display()));
    }
    Ok(())
}
fn present(path: &Path) -> Result<bool, String> {
    crate::native::hook_files::plain_ancestors(path)?;
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(format!("许可存储路径不是普通文件：{}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("检查许可存储 {}：{error}", path.display())),
    }
}
pub fn modern_file(
    system: &Path,
    configured: Option<&Path>,
    filename: &str,
) -> Result<PathBuf, String> {
    absolute(system)?;
    if !matches!(filename, "data.dat" | "tokens.dat") {
        return Err("未知许可存储文件名".into());
    }
    if let Some(directory) = configured {
        absolute(directory)?;
        let path = directory.join(filename);
        if present(&path)? {
            return Ok(path);
        }
    }
    for directory in FALLBACKS {
        let path = system.join(directory).join(filename);
        if present(&path)? {
            return Ok(path);
        }
    }
    Err(format!("未找到 Windows 许可存储 {filename}"))
}
pub fn physical(build: u32, system: &Path, configured: Option<&Path>) -> Result<Physical, String> {
    absolute(system)?;
    let version = Version::detect(build).map_err(|e| e.to_string())?;
    if !version.paired() {
        return Ok(Physical {
            version,
            paths: vec![modern_file(system, configured, "data.dat")?],
            service: "sppsvc",
            missing_secondary: false,
        });
    }
    // Select index 0 explicitly: directory enumeration order must not swap the
    // authoritative primary and mirror (upstream uses the -0. -> -1. pair).
    let primary = system.join(PRIMARY);
    if !present(&primary)? {
        return Err(format!("未找到旧版主存储：{}", primary.display()));
    }
    let secondary = system.join(SECONDARY);
    let missing_secondary = !present(&secondary)?;
    Ok(Physical {
        version,
        paths: vec![primary, secondary],
        service: if version == Version::Vista {
            "slsvc"
        } else {
            "sppsvc"
        },
        missing_secondary,
    })
}
pub fn tokens(
    version: Version,
    windows: &Path,
    system: &Path,
    configured: Option<&Path>,
) -> Result<PathBuf, String> {
    absolute(windows)?;
    let legacy = match version {
        Version::Vista => Some("SoftwareLicensing"),
        Version::Win7 => Some("SoftwareProtectionPlatform"),
        _ => None,
    };
    if let Some(name) = legacy {
        let path = windows
            .join("ServiceProfiles/NetworkService/AppData/Roaming/Microsoft")
            .join(name)
            .join("tokens.dat");
        if !present(&path)? {
            return Err(format!("未找到旧版令牌存储：{}", path.display()));
        }
        Ok(path)
    } else {
        modern_file(system, configured, "tokens.dat")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn file(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "fixture").unwrap();
    }
    #[test]
    fn modern_resolution_prefers_configured_path_then_upstream_directory_order() {
        let temp = tempfile::tempdir().unwrap();
        let system = temp.path().join("System32");
        let config = temp.path().join("Configured");
        for relative in FALLBACKS {
            file(&system.join(relative).join("data.dat"));
        }
        assert_eq!(
            modern_file(&system, Some(&config), "data.dat").unwrap(),
            system.join("spp/store/data.dat")
        );
        file(&config.join("data.dat"));
        assert_eq!(
            modern_file(&system, Some(&config), "data.dat").unwrap(),
            config.join("data.dat")
        );
        for relative in FALLBACKS {
            let expected = system.join(relative).join("data.dat");
            assert_eq!(modern_file(&system, None, "data.dat").unwrap(), expected);
            std::fs::remove_file(expected).unwrap();
        }
        assert!(modern_file(&system, None, "data.dat").is_err());
        assert!(modern_file(&system, Some(Path::new("relative")), "data.dat").is_err());
        assert!(modern_file(&system, None, "../data.dat").is_err());
    }
    #[test]
    fn paired_layout_requires_primary_and_records_missing_secondary_without_creating_it() {
        let temp = tempfile::tempdir().unwrap();
        file(&temp.path().join(SECONDARY));
        assert!(physical(7601, temp.path(), None).is_err());
        file(&temp.path().join(PRIMARY));
        for (build, service) in [(6002, "slsvc"), (7601, "sppsvc")] {
            let layout = physical(build, temp.path(), None).unwrap();
            assert_eq!(layout.service, service);
            assert!(layout.version.paired());
            assert_eq!(
                layout.paths,
                [temp.path().join(PRIMARY), temp.path().join(SECONDARY)]
            );
            assert!(!layout.missing_secondary);
        }
        std::fs::remove_file(temp.path().join(SECONDARY)).unwrap();
        assert!(physical(7601, temp.path(), None).unwrap().missing_secondary);
        assert!(!temp.path().join(SECONDARY).exists());
        assert!(physical(7603, temp.path(), None).is_err());
    }
    #[test]
    fn malformed_store_directory_is_not_silently_skipped() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("configured");
        std::fs::create_dir_all(configured.join("data.dat")).unwrap();
        file(&temp.path().join("spp/store/data.dat"));
        assert!(
            modern_file(temp.path(), Some(&configured), "data.dat")
                .unwrap_err()
                .contains("不是普通文件")
        );
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_store_cannot_redirect_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        file(&target);
        std::fs::create_dir_all(temp.path().join("spp/store")).unwrap();
        std::os::unix::fs::symlink(&target, temp.path().join("spp/store/data.dat")).unwrap();
        assert!(
            modern_file(temp.path(), None, "data.dat")
                .unwrap_err()
                .contains("重解析点")
        );
        assert_eq!(std::fs::read(target).unwrap(), b"fixture");
    }
    #[cfg(windows)]
    #[test]
    fn actual_modern_path_resolution_is_read_only() {
        let path = super::super::runtime::store_path("data.dat").unwrap();
        assert!(path.is_absolute() && path.is_file());
        assert_eq!(path.file_name().unwrap(), "data.dat");
    }
    #[test]
    fn token_paths_are_version_specific_and_independent_of_physical_store() {
        let temp = tempfile::tempdir().unwrap();
        let system = temp.path().join("System32");
        for (version, directory) in [
            (Version::Vista, "SoftwareLicensing"),
            (Version::Win7, "SoftwareProtectionPlatform"),
        ] {
            let expected = temp
                .path()
                .join("ServiceProfiles/NetworkService/AppData/Roaming/Microsoft")
                .join(directory)
                .join("tokens.dat");
            file(&expected);
            assert_eq!(
                tokens(version, temp.path(), &system, None).unwrap(),
                expected
            );
        }
        file(&system.join("spp/store/tokens.dat"));
        file(&system.join("spp/store/data.dat"));
        for build in [9200, 9600, 26100] {
            let layout = physical(build, &system, None).unwrap();
            assert_eq!(layout.service, "sppsvc");
            assert_eq!(layout.paths.len(), 1);
            assert_eq!(
                tokens(layout.version, temp.path(), &system, None).unwrap(),
                system.join("spp/store/tokens.dat")
            );
        }
        std::fs::remove_file(system.join("spp/store/tokens.dat")).unwrap();
        assert!(physical(26100, &system, None).is_ok());
        assert!(tokens(Version::Modern, temp.path(), &system, None).is_err());
    }
}
