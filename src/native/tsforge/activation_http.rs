//! Synchronous WinHTTP transport for the fixed Microsoft BatchActivation endpoint.
#![allow(dead_code)]
use super::activation_ws::{self, RequestType, Response};
use std::{
    ffi::c_void,
    io, ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinHttp::*;
struct Handle(*mut c_void);
impl Handle {
    fn new(value: *mut c_void) -> io::Result<Self> {
        if value.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(value))
        }
    }
    fn option(&self, option: u32, value: u32) -> io::Result<()> {
        checked(unsafe { WinHttpSetOption(self.0, option, (&value as *const u32).cast(), 4) })
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn checked(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn session() -> io::Result<Handle> {
    let session = Handle::new(unsafe {
        WinHttpOpen(
            wide("MAS-Rust").as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        )
    })?;
    checked(unsafe { WinHttpSetTimeouts(session.0, 30000, 30000, 30000, 30000) })?;
    session.option(
        WINHTTP_OPTION_SECURE_PROTOCOLS,
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    )?;
    Ok(session)
}
pub fn call(kind: RequestType, iid: &str, epid: &str) -> io::Result<Response> {
    let body = activation_ws::request(kind, iid, epid)?;
    let session = session()?;
    let connection = Handle::new(unsafe {
        WinHttpConnect(
            session.0,
            wide("activation.sls.microsoft.com").as_ptr(),
            443,
            0,
        )
    })?;
    let request = Handle::new(unsafe {
        WinHttpOpenRequest(
            connection.0,
            wide("POST").as_ptr(),
            wide("/BatchActivation/BatchActivation.asmx").as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            WINHTTP_FLAG_SECURE,
        )
    })?;
    request.option(
        WINHTTP_OPTION_REDIRECT_POLICY,
        WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
    )?;
    // Default certificate validation stays enabled; never accept invalid TLS.
    let headers = wide(&format!(
        "Content-Type: text/xml; charset=\"utf-8\"\r\nAccept: text/xml\r\nSOAPAction: {}\r\n",
        activation_ws::ACTION
    ));
    let start = Instant::now();
    checked(unsafe {
        WinHttpSendRequest(
            request.0,
            headers.as_ptr(),
            headers.len() as u32 - 1,
            body.as_ptr().cast(),
            body.len() as u32,
            body.len() as u32,
            0,
        )
    })?;
    checked(unsafe { WinHttpReceiveResponse(request.0, ptr::null_mut()) })?;
    let mut status = 0u32;
    let mut length = 4;
    checked(unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            (&mut status as *mut u32).cast(),
            &mut length,
            ptr::null_mut(),
        )
    })?;
    if status != 200 {
        return Err(io::Error::other(format!("activation HTTP status {status}")));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        if start.elapsed() > Duration::from_secs(120) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "activation response deadline exceeded",
            ));
        }
        let mut read = 0;
        checked(unsafe {
            WinHttpReadData(
                request.0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
            )
        })?;
        if read == 0 {
            break;
        }
        if bytes.len() + read as usize > activation_ws::MAX_RESPONSE {
            return Err(io::Error::other("activation response exceeds size limit"));
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
    }
    activation_ws::response(&activation_ws::decode_text(&bytes)?)
}
#[cfg(test)]
mod tests {
    #[test]
    fn native_session_accepts_proxy_timeout_and_tls_configuration_without_network_request() {
        let _session = super::session().unwrap();
    }
}
