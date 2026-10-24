#[path = "build_support/pe.rs"]
mod pe;

fn build_hooks() {
    use std::{path::PathBuf, process::Command};
    let rustc = std::env::var_os("RUSTC").expect("RUSTC");
    let sysroot = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc sysroot");
    assert!(sysroot.status.success());
    let sysroot = PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim());
    let host = std::env::var("HOST").unwrap();
    let linker =
        sysroot
            .join("lib/rustlib")
            .join(&host)
            .join("bin")
            .join(if host.contains("windows") {
                "rust-lld.exe"
            } else {
                "rust-lld"
            });
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let definition = std::fs::read_to_string("vendor/ohook-rs/sppc.def").unwrap();
    for (target, name, machine) in [
        ("x86_64-pc-windows-msvc", "sppc64.dll", 0x8664),
        ("i686-pc-windows-msvc", "sppc32.dll", 0x14c),
    ] {
        let output = out.join(name);
        let result = Command::new(&rustc)
            .args([
                "--edition=2021",
                "--crate-name",
                "shook",
                "--crate-type",
                "cdylib",
                "vendor/ohook-rs/src/lib.rs",
                "--target",
                target,
                "-C",
                "opt-level=z",
                "-C",
                "lto=fat",
                "-C",
                "codegen-units=1",
                "-C",
                "panic=abort",
                "-C",
                "strip=symbols",
                "-C",
                "link-arg=/DEF:vendor/ohook-rs/sppc.def",
                "-C",
                "link-arg=/Brepro",
                "-C",
                "link-arg=/NODEFAULTLIB",
                "-C",
            ])
            .arg(format!("linker={}", linker.display()))
            .arg("-o")
            .arg(&output)
            .output()
            .expect("build Rust Ohook DLL");
        assert!(
            result.status.success(),
            "Rust DLL build failed. Install targets with rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc.\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
        pe::verify(&std::fs::read(&output).unwrap(), machine, &definition)
            .expect("Ohook PE export verification");
        for (source, suffix, crate_type) in [
            ("provider.rs", "provider.dll", "cdylib"),
            ("runner.rs", "runner.exe", "bin"),
        ] {
            let artifact = out.join(format!("{name}-{suffix}"));
            let mut command = Command::new(&rustc);
            command
                .args([
                    "--edition=2021",
                    "--crate-type",
                    crate_type,
                    "--target",
                    target,
                    "-C",
                    "opt-level=z",
                    "-C",
                    "lto=fat",
                    "-C",
                    "codegen-units=1",
                    "-C",
                    "panic=abort",
                    "-C",
                    "strip=symbols",
                    "-C",
                    "link-arg=/NODEFAULTLIB",
                    "-C",
                ])
                .arg(format!("linker={}", linker.display()));
            if crate_type == "bin" {
                command.args([
                    "-C",
                    "link-arg=/ENTRY:mainCRTStartup",
                    "-C",
                    "link-arg=/SUBSYSTEM:CONSOLE",
                ]);
            }
            let result = command
                .arg(format!("tests/hook_fixture/{source}"))
                .arg("-o")
                .arg(&artifact)
                .output()
                .expect("build isolated hook test fixture");
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");

    println!("cargo:rerun-if-changed=vendor/ohook-rs");
    println!("cargo:rerun-if-changed=build_support/pe.rs");
    println!("cargo:rerun-if-changed=tests/hook_fixture");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        build_hooks();
        let mut resource = winresource::WindowsResource::new();
        resource
            .set_icon("assets/app.ico")
            .set("ProductName", "MAS Rust")
            .set("FileDescription", "Windows 与 Office 授权管理工具")
            .set("LegalCopyright", "MAS Rust contributors")
            .set_manifest(
                r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="0.6.0.5" processorArchitecture="*" name="MAS.Rust" type="win32"/>
  <description>MAS Rust</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>"#,
            );
        if let Err(error) = resource.compile() {
            panic!("无法嵌入 Windows 资源: {error}");
        }
    }
}
