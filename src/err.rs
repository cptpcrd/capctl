use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Represents an OS error encountered when performing an operation.
///
/// Note: Parsing errors (i.e. errors returned by `FromStr` implementations) have their own types;
/// for example [`ParseCapError`]).
///
/// [`ParseCapError`]: ./caps/struct.ParseCapError.html
pub struct Error(i32);

impl Error {
    /// Get the last OS error that occured (i.e. the current `errno` value).
    #[inline]
    pub fn last() -> Self {
        Self(unsafe { *libc::__errno_location() })
    }

    /// Construct an `Error` from an `errno` code.
    #[inline]
    pub fn from_code(eno: i32) -> Self {
        Self(eno)
    }

    /// Get the `errno` code represented by this `Error` object.
    #[inline]
    pub fn code(&self) -> i32 {
        self.0
    }

    fn strerror(&self) -> &'static str {
        unsafe { std::ffi::CStr::from_ptr(libc::strerror(self.0)) }
            .to_str()
            .unwrap()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.strerror())?;
        write!(f, " (code {})", self.0)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Error")
            .field("code", &self.0)
            .field("message", &self.strerror())
            .finish()
    }
}

impl std::error::Error for Error {
    #[inline]
    fn description(&self) -> &str {
        self.strerror()
    }
}

impl From<Error> for std::io::Error {
    #[inline]
    fn from(e: Error) -> Self {
        Self::from_raw_os_error(e.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code() {
        assert_eq!(Error::from_code(libc::EPERM).code(), libc::EPERM);
        assert_eq!(Error::from_code(libc::ENOENT).code(), libc::ENOENT);
    }

    #[test]
    fn test_last() {
        unsafe {
            *libc::__errno_location() = libc::EPERM;
        }
        assert_eq!(Error::last().code(), libc::EPERM);

        unsafe {
            *libc::__errno_location() = libc::ENOENT;
        }
        assert_eq!(Error::last().code(), libc::ENOENT);
    }

    #[test]
    fn test_strerror() {
        assert_eq!(Error::from_code(libc::EISDIR).strerror(), "Is a directory");

        #[allow(deprecated)]
        {
            use std::error::Error;
            assert_eq!(
                super::Error::from_code(libc::EISDIR).description(),
                "Is a directory"
            );
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(
            Error::from_code(libc::EISDIR).to_string(),
            format!("Is a directory (code {})", libc::EISDIR)
        );
    }

    #[test]
    fn test_debug() {
        assert_eq!(
            format!("{:?}", Error::from_code(libc::EISDIR)),
            format!(
                "Error {{ code: {}, message: \"Is a directory\" }}",
                libc::EISDIR
            )
        );
    }

    #[test]
    fn test_from_error() {
        assert_eq!(
            std::io::Error::from(Error::from_code(libc::ENOENT)).raw_os_error(),
            Some(libc::ENOENT)
        );
    }
}
