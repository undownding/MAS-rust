//! Small x86/x64 process exercising the real hook with the isolated fake provider.
#![no_std]
#![no_main]
use core::ffi::c_void;
#[repr(C)]
struct Status {
    sku: [u32; 4],
    status: i32,
    grace: u32,
    total: u32,
    reason: i32,
    expires: u64,
}
#[cfg_attr(
    target_arch = "x86",
    link(
        name = "KERNEL32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )
)]
#[cfg_attr(not(target_arch = "x86"), link(name = "KERNEL32", kind = "raw-dylib"))]
extern "system" {
    fn LoadLibraryW(path: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn ExitProcess(code: u32) -> !;
}
#[no_mangle]
unsafe extern "C" fn mainCRTStartup() -> ! {
    let path = [115u16, 112, 112, 99, 46, 100, 108, 108, 0];
    let module = LoadLibraryW(path.as_ptr());
    if module.is_null() {
        ExitProcess(10);
    }
    let address = GetProcAddress(module, b"SLGetLicensingStatusInformation\0".as_ptr());
    if address.is_null() {
        ExitProcess(11);
    }
    type Hook = unsafe extern "system" fn(
        *const c_void,
        *const c_void,
        *const c_void,
        *const u16,
        *mut u32,
        *mut *mut Status,
    ) -> i32;
    let hook: Hook = core::mem::transmute(address);
    let mut count = 0;
    let mut data = core::ptr::null_mut();
    let null = core::ptr::null();
    if hook(
        1usize as *const c_void,
        null,
        null,
        core::ptr::null(),
        &mut count,
        &mut data,
    ) != 0x80070005u32 as i32
    {
        ExitProcess(12);
    }
    if hook(null, null, null, core::ptr::null(), &mut count, &mut data) != 0
        || count != 3
        || data.is_null()
    {
        ExitProcess(13);
    }
    if (*data).status != 0 || (*data).grace != 12 {
        ExitProcess(14);
    }
    if (*data.add(1)).status != 1 || (*data.add(1)).grace != 12 || (*data.add(1)).expires != 78 {
        ExitProcess(15);
    }
    let licensed = &*data.add(2);
    if licensed.status != 1
        || licensed.grace != 0
        || licensed.total != 0
        || licensed.reason != 0
        || licensed.expires != 0
    {
        ExitProcess(16);
    }
    ExitProcess(0)
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        ExitProcess(99);
    }
}
