fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set_icon("assets/app.ico")
            .set("ProductName", "MAS Rust")
            .set("FileDescription", "Windows 与 Office 授权管理工具")
            .set("LegalCopyright", "MAS Rust contributors")
            .set_manifest(
                r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="0.1.0.0" processorArchitecture="*" name="MAS.Rust" type="win32"/>
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
