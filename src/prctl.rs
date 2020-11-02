use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::prelude::*;

pub fn set_name<N: AsRef<OsStr>>(name: N) -> io::Result<()> {
    let name = name.as_ref().as_bytes();
    let mut ptr: *const u8 = name.as_ptr();

    let mut buf = [0; 16];
    if name.len() < 16 {
        buf[..name.len()].copy_from_slice(name);
        ptr = buf.as_ptr();
    }

    unsafe { crate::raw_prctl(libc::PR_SET_NAME, ptr as libc::c_ulong, 0, 0, 0) }?;

    Ok(())
}

pub fn get_name() -> io::Result<OsString> {
    let mut name_vec = vec![0; 16];
    unsafe {
        crate::raw_prctl(
            libc::PR_GET_NAME,
            name_vec.as_ptr() as libc::c_ulong,
            0,
            0,
            0,
        )
    }?;

    name_vec.truncate(name_vec.iter().position(|x| *x == 0).unwrap());

    Ok(OsString::from_vec(name_vec))
}

#[inline]
pub fn get_no_new_privs() -> io::Result<bool> {
    let res = unsafe { crate::raw_prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }?;

    Ok(res != 0)
}

#[inline]
pub fn set_no_new_privs() -> io::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }?;

    Ok(())
}

#[inline]
pub fn get_keepcaps() -> io::Result<bool> {
    let res = unsafe { crate::raw_prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0) }?;

    Ok(res != 0)
}

#[inline]
pub fn set_keepcaps(keep: bool) -> io::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_SET_KEEPCAPS, keep as libc::c_ulong, 0, 0, 0) }?;

    Ok(())
}

#[inline]
pub fn get_dumpable() -> io::Result<bool> {
    let res = unsafe { crate::raw_prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }?;

    Ok(res != 0)
}

#[inline]
pub fn set_dumpable(dumpable: bool) -> io::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_SET_DUMPABLE, dumpable as libc::c_ulong, 0, 0, 0) }?;

    Ok(())
}

#[inline]
pub fn set_subreaper(flag: bool) -> io::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_SET_CHILD_SUBREAPER, flag as libc::c_ulong, 0, 0, 0) }?;

    Ok(())
}

#[inline]
pub fn get_subreaper() -> io::Result<bool> {
    let mut res = 0;

    unsafe {
        crate::raw_prctl(
            libc::PR_GET_CHILD_SUBREAPER,
            (&mut res) as *mut libc::c_int as libc::c_ulong,
            0,
            0,
            0,
        )
    }?;

    Ok(res != 0)
}

#[inline]
pub fn set_pdeathsig(sig: Option<libc::c_int>) -> io::Result<()> {
    unsafe {
        crate::raw_prctl(
            libc::PR_SET_PDEATHSIG,
            sig.unwrap_or(0) as libc::c_ulong,
            0,
            0,
            0,
        )
    }?;

    Ok(())
}

#[inline]
pub fn get_pdeathsig() -> io::Result<Option<libc::c_int>> {
    let mut sig = 0;

    unsafe {
        crate::raw_prctl(
            libc::PR_GET_PDEATHSIG,
            (&mut sig) as *mut libc::c_int as libc::c_ulong,
            0,
            0,
            0,
        )
    }?;

    Ok(if sig == 0 { None } else { Some(sig) })
}

bitflags::bitflags! {
    pub struct Secbits: libc::c_ulong {
        const NOROOT = 0x1;
        const NOROOT_LOCKED = 0x2;

        const NO_SETUID_FIXUP = 0x4;
        const NO_SETUID_FIXUP_LOCKED = 0x8;

        const KEEP_CAPS = 0x10;
        const KEEP_CAPS_LOCKED = 0x20;

        const NO_CAP_AMBIENT_RAISE = 0x40;
        const NO_CAP_AMBIENT_RAISE_LOCKED = 0x80;
    }
}

pub fn get_securebits() -> io::Result<Secbits> {
    let f = unsafe { crate::raw_prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) }?;

    Ok(Secbits::from_bits_truncate(f as libc::c_ulong))
}

pub fn set_securebits(flags: Secbits) -> io::Result<()> {
    unsafe { crate::raw_prctl(libc::PR_SET_SECUREBITS, flags.bits(), 0, 0, 0) }?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepcaps() {
        let old_keepcaps = get_keepcaps().unwrap();

        set_keepcaps(true).unwrap();
        assert!(get_keepcaps().unwrap());
        assert!(get_securebits().unwrap().contains(Secbits::KEEP_CAPS));

        set_keepcaps(false).unwrap();
        assert!(!get_keepcaps().unwrap());
        assert!(!get_securebits().unwrap().contains(Secbits::KEEP_CAPS));

        set_keepcaps(old_keepcaps).unwrap();
    }

    #[test]
    fn test_nnp() {
        set_no_new_privs();
        assert!(get_no_new_privs().unwrap());
        set_no_new_privs();
        assert!(get_no_new_privs().unwrap());
    }

    #[test]
    fn test_subreaper() {
        let was_subreaper = get_subreaper().unwrap();

        set_subreaper(false).unwrap();
        assert!(!get_subreaper().unwrap());
        set_subreaper(true).unwrap();
        assert!(get_subreaper().unwrap());

        set_subreaper(was_subreaper).unwrap();
    }

    #[test]
    fn test_pdeathsig() {
        let orig_pdeathsig = get_pdeathsig().unwrap();

        set_pdeathsig(None).unwrap();
        assert_eq!(get_pdeathsig().unwrap(), None);
        set_pdeathsig(Some(0)).unwrap();
        assert_eq!(get_pdeathsig().unwrap(), None);

        set_pdeathsig(Some(libc::SIGCHLD)).unwrap();
        assert_eq!(get_pdeathsig().unwrap(), Some(libc::SIGCHLD));

        set_pdeathsig(orig_pdeathsig).unwrap();
    }

    #[test]
    fn test_dumpable() {
        assert!(get_dumpable().unwrap());
        // We can't set it to false because somebody may be ptrace()ing us during testing
        set_dumpable(true).unwrap();
        assert!(get_dumpable().unwrap());
    }

    #[test]
    fn test_name() {
        let orig_name = get_name().unwrap();

        set_name("capctl-short").unwrap();
        assert_eq!(get_name().unwrap(), "capctl-short");

        set_name("capctl-very-very-long").unwrap();
        assert_eq!(get_name().unwrap(), "capctl-very-ver");

        set_name(&orig_name).unwrap();
        assert_eq!(get_name().unwrap(), orig_name);
    }
}
