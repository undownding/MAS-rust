//! Microsoft.Office.Desktop dependency mapping from :ts_off (MAS 3.12).
#![cfg_attr(not(test), allow(dead_code))]
pub fn products(dependencies: &[String], license_names: &[String]) -> Vec<String> {
    let dependencies = dependencies.join(" ").to_ascii_lowercase();
    let mut products = Vec::new();
    if [
        "access",
        "excel",
        "onenote",
        "outlook",
        "powerpoint",
        "publisher",
        "skypeforbusiness",
        "word",
    ]
    .iter()
    .any(|name| dependencies.contains(name))
    {
        products.push("O365HomePremRetail".into());
    }
    for product in ["Project", "Visio"] {
        if !dependencies.contains(&product.to_ascii_lowercase()) {
            continue;
        }
        let year = ["2024", "2021", "2019"]
            .into_iter()
            .find(|year| {
                let prefix = format!("{product}Pro{year}VL").to_ascii_lowercase();
                license_names.iter().any(|name| {
                    let name = name.to_ascii_lowercase();
                    name.starts_with(&prefix) && name.ends_with(".xrm-ms")
                })
            })
            .unwrap_or("");
        products.push(format!("{product}Pro{year}Retail"));
    }
    products
}

#[cfg(windows)]
pub struct Installation {
    pub root: std::path::PathBuf,
    pub licenses: std::path::PathBuf,
    pub products: Vec<String>,
}
#[cfg(windows)]
pub fn discover(build: u32) -> Result<Vec<Installation>, String> {
    if build < 10240 {
        return Ok(Vec::new());
    }
    // Scope is the current user, matching Get-AppxPackage without -AllUsers.
    // Explicit WinRT iteration preserves HRESULTs instead of dropping failures.
    fn query() -> Result<Vec<Installation>, String> {
        use windows::{Management::Deployment::PackageManager, core::HSTRING};
        let query = (|| -> windows::core::Result<Vec<(std::path::PathBuf, Vec<String>)>> {
            let manager = PackageManager::new()?;
            let packages = manager.FindPackagesByUserSecurityId(&HSTRING::new())?;
            let iterator = packages.First()?;
            let mut result = Vec::new();
            while iterator.HasCurrent()? {
                let package = iterator.Current()?;
                if package
                    .Id()?
                    .Name()?
                    .to_string()
                    .eq_ignore_ascii_case("Microsoft.Office.Desktop")
                {
                    let root =
                        std::path::PathBuf::from(package.InstalledLocation()?.Path()?.to_string());
                    // Upstream uses this file to identify the desktop payload.
                    if root.is_absolute()
                        && root.join("Integration").join("Integrator.exe").is_file()
                    {
                        let deps = package.Dependencies()?;
                        let mut dependencies = Vec::new();
                        for index in 0..deps.Size()? {
                            dependencies.push(deps.GetAt(index)?.Id()?.FullName()?.to_string());
                        }
                        result.push((root, dependencies));
                    }
                }
                iterator.MoveNext()?;
            }
            Ok(result)
        })()
        .map_err(|e| format!("读取 Office UWP 包信息：{e}"))?;
        query
            .into_iter()
            .map(|(root, dependencies)| {
                let licenses = root.join("Licenses16");
                let files = crate::native::office_catalog::license_files(&licenses)?;
                let names = files
                    .iter()
                    .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                let products = products(&dependencies, &names);
                if products.is_empty() {
                    return Err(format!("Office UWP 未找到产品 ID：{}", root.display()));
                }
                Ok(Installation {
                    root,
                    licenses,
                    products,
                })
            })
            .collect()
    }
    use windows::Win32::System::WinRT::{
        RO_INIT_MULTITHREADED, RO_INIT_SINGLETHREADED, RoInitialize, RoUninitialize,
    };
    // WMI can already have initialized this thread. Balance every successful
    // RoInitialize (including S_FALSE), retaining the existing apartment model.
    let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    if let Err(error) = initialized {
        if error.code() != windows::Win32::Foundation::RPC_E_CHANGED_MODE {
            return Err(format!("初始化 Office UWP 查询：{error}"));
        }
        unsafe { RoInitialize(RO_INIT_SINGLETHREADED) }
            .map_err(|e| format!("初始化 Office UWP 查询：{e}"))?;
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { RoUninitialize() };
        }
    }
    let _apartment = Apartment;
    query()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn desktop_apps_collapse_into_one_subscription_and_dependencies_are_case_insensitive() {
        let deps = strings(&[
            "Microsoft.Office.Desktop.Word_16_x64",
            "Microsoft.Office.Desktop.EXCEL_16_x64",
            "Microsoft.Office.Desktop.Project_16_x64",
        ]);
        assert_eq!(
            products(&deps, &[]),
            ["O365HomePremRetail", "ProjectProRetail"]
        );
        assert!(products(&strings(&["Microsoft.Office.Desktop.Framework_16"]), &[]).is_empty());
        for app in [
            "Access",
            "Excel",
            "OneNote",
            "Outlook",
            "PowerPoint",
            "Publisher",
            "SkypeForBusiness",
            "Word",
        ] {
            assert_eq!(
                products(&[format!("Microsoft.Office.Desktop.{app}_16")], &[]),
                ["O365HomePremRetail"]
            );
        }
    }
    #[test]
    fn project_visio_each_pick_latest_available_license_and_require_dependency() {
        let deps = strings(&[
            "Microsoft.Office.Desktop.Project_16",
            "Microsoft.Office.Desktop.Visio_16",
        ]);
        let names = strings(&[
            "ProjectPro2019VL_test.xrm-ms",
            "ProjectPro2024VL_test.xrm-ms",
            "VisioPro2021VL_test.xrm-ms",
            "VisioPro2024VL_test.txt",
        ]);
        assert_eq!(
            products(&deps, &names),
            ["ProjectPro2024Retail", "VisioPro2021Retail"]
        );
        assert!(products(&[], &names).is_empty());
        assert_eq!(
            products(&deps, &strings(&["PROJECTPRO2019VL_TEST.XRM-MS"])),
            ["ProjectPro2019Retail", "VisioProRetail"]
        );
        assert_eq!(
            products(&deps, &strings(&["ProjectPro2024PreviewVL_test.xrm-ms"])),
            ["ProjectProRetail", "VisioProRetail"]
        );
    }
    #[cfg(windows)]
    #[test]
    fn real_package_discovery_is_read_only_and_old_builds_skip_winrt() {
        assert!(discover(9600).unwrap().is_empty());
        let com = crate::native::licensing::Licensing::new().unwrap();
        for install in discover(10240).unwrap() {
            assert!(install.root.is_absolute());
            assert!(!install.products.is_empty());
            assert!(install.licenses.ends_with("Licenses16"));
        }
        // WinRT cleanup must not tear down WMI's existing COM apartment.
        assert!(
            !com.query("SELECT BuildNumber FROM Win32_OperatingSystem")
                .unwrap()
                .is_empty()
        );
    }
}
