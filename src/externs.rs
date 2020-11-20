extern "C" {
    pub fn capget(hdrp: *mut cap_user_header_t, datap: *mut cap_user_data_t) -> libc::c_int;

    pub fn capset(hdrp: *mut cap_user_header_t, datap: *const cap_user_data_t) -> libc::c_int;
}

#[repr(C)]
pub struct cap_user_header_t {
    pub version: u32,
    pub pid: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct cap_user_data_t {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}
