use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW,
};
use windows::core::{Error, PCWSTR};

struct FindHandle(HANDLE);
impl Drop for FindHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = FindClose(self.0);
        };
    }
}

pub fn enumerate_dir_entries<P, F>(pattern: P, mut cb: F) -> windows::core::Result<()>
where
    P: AsRef<OsStr>,
    F: FnMut(&WIN32_FIND_DATAW),
{
    unsafe {
        let mut fd: WIN32_FIND_DATAW = std::mem::zeroed();
        let wide: Vec<u16> = pattern
            .as_ref()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let h_find = FindFirstFileW(PCWSTR(wide.as_ptr()), &mut fd as *mut _).map_err(|e| e)?;
        let _h_find = FindHandle(h_find);
        loop {
            cb(&fd);
            if FindNextFileW(_h_find.0, &mut fd as *mut _).is_err() {
                break;
            }
        }
        let le = GetLastError();
        if le != ERROR_NO_MORE_FILES {
            Err(Error::from(le))
        } else {
            Ok(())
        }
    }
}

pub fn name_from_find(fd: &WIN32_FIND_DATAW) -> OsString {
    let len = fd
        .cFileName
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fd.cFileName.len());
    OsString::from_wide(&fd.cFileName[..len])
}
