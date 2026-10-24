//! Isolated fake SPP provider: no licensing service calls, just owned test data.
#![no_std]
use core::ffi::c_void;
#[repr(C)]
#[derive(Clone, Copy)]
struct Status {
    sku: [u32; 4],
    status: i32,
    grace: u32,
    total: u32,
    reason: i32,
    expires: u64,
}
static mut STATUS: [Status; 3] = [Status {
    sku: [0; 4],
    status: 0,
    grace: 12,
    total: 34,
    reason: 56,
    expires: 78,
}; 3];
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
    fn LocalAlloc(flags: u32, size: usize) -> *mut c_void;
}
#[no_mangle]
unsafe extern "system" fn SLGetLicensingStatusInformation(
    handle: *const c_void,
    _app: *const c_void,
    _sku: *const c_void,
    _right: *const u16,
    count: *mut u32,
    out: *mut *mut Status,
) -> i32 {
    if handle as usize == 1 {
        return 0x80070005u32 as i32;
    }
    let data = core::ptr::addr_of_mut!(STATUS).cast::<Status>();
    for i in 0..3 {
        data.add(i).write(Status {
            sku: [i as u32, 0, 0, 0],
            status: i as i32,
            grace: 12,
            total: 34,
            reason: 56,
            expires: 78,
        });
    }
    *count = 3;
    *out = data;
    0
}
#[no_mangle]
unsafe extern "system" fn SLGetProductSkuInformation(
    _handle: *const c_void,
    sku: *const [u32; 4],
    _name: *const u16,
    _kind: *mut u32,
    size: *mut u32,
    out: *mut *mut u8,
) -> i32 {
    let name: &[u16] = if (*sku)[0] == 1 {
        &[71, 114, 97, 99, 101, 0]
    } else {
        &[79, 102, 102, 105, 99, 101, 0]
    };
    *size = (name.len() * 2) as u32;
    let buffer = LocalAlloc(0, *size as usize).cast::<u16>();
    if buffer.is_null() {
        return 0x8007000eu32 as i32;
    }
    for (i, c) in name.iter().enumerate() {
        buffer.add(i).write(*c);
    }
    *out = buffer.cast();
    0
}
#[no_mangle]
extern "system" fn _DllMainCRTStartup(_: *const u8, _: u32, _: *const u8) -> u32 {
    1
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
