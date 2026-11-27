//! Native OS process & memory hardening (zero extra third-party crates).
//!
//! Suppresses OS crash/core memory dumps and activates host exploit/injection
//! mitigations using direct kernel32 (Windows) / libc (Linux) FFI calls:
//! - Windows: `SetErrorMode`, dynamic `wer.dll!WerSetFlags(WER_FAULT_REPORTING_NO_UI)`,
//!   and `SetProcessMitigationPolicy` (`ProcessDynamicCodePolicy` ACG +
//!   `ProcessExtensionPointDisablePolicy`).
//! - Linux: `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, 0)`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsHardeningReport {
    pub dumps_suppressed: bool,
    pub dynamic_code_prohibited: bool,
    pub extension_points_disabled: bool,
}

#[cfg(windows)]
mod platform {
    use super::OsHardeningReport;
    use std::ffi::{c_char, c_void};

    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;
    const WER_FAULT_REPORTING_NO_UI: u32 = 0x0020;

    // winnt.h PROCESS_MITIGATION_POLICY ordinals
    const PROCESS_DYNAMIC_CODE_POLICY: u32 = 2;
    const PROCESS_EXTENSION_POINT_DISABLE_POLICY: u32 = 6;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetErrorMode(u_mode: u32) -> u32;
        fn SetProcessMitigationPolicy(
            mitigation_policy: u32,
            lp_buffer: *const c_void,
            dw_length: usize,
        ) -> i32;
        fn LoadLibraryA(lp_lib_file_name: *const c_char) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const c_char) -> *mut c_void;
    }

    pub fn suppress_crash_dumps() -> bool {
        // SAFETY: Setting process error mode bitmask takes no pointers and is thread-safe per-process.
        unsafe {
            SetErrorMode(
                SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX,
            );
        }
        // Try dynamic wer.dll!WerSetFlags(WER_FAULT_REPORTING_NO_UI) so no extra
        // import-table DLL requirement is added on stripped Server/Core hosts.
        // SAFETY: Passing static NUL-terminated ASCII library/symbol names; checking null pointers.
        unsafe {
            let wer = LoadLibraryA(c"wer.dll".as_ptr());
            if wer.is_null() {
                return true; // SetErrorMode succeeded even if wer.dll absent
            }
            let sym = GetProcAddress(wer, c"WerSetFlags".as_ptr());
            if sym.is_null() {
                return true;
            }
            let wer_set_flags: extern "system" fn(u32) -> i32 = std::mem::transmute(sym);
            let _ = wer_set_flags(WER_FAULT_REPORTING_NO_UI);
        }
        true
    }

    pub fn apply_process_mitigations() -> (bool, bool) {
        let mut dyn_ok = false;
        let mut ext_ok = false;
        // Both PROCESS_MITIGATION_DYNAMIC_CODE_POLICY and
        // PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY are single 32-bit Flags bitfields.
        let flags_one: u32 = 1;
        // SAFETY: Passing stack-allocated 4-byte policy structs with exact byte size.
        unsafe {
            if SetProcessMitigationPolicy(
                PROCESS_DYNAMIC_CODE_POLICY,
                (&flags_one as *const u32).cast::<c_void>(),
                std::mem::size_of::<u32>(),
            ) != 0
            {
                dyn_ok = true;
            }
            if SetProcessMitigationPolicy(
                PROCESS_EXTENSION_POINT_DISABLE_POLICY,
                (&flags_one as *const u32).cast::<c_void>(),
                std::mem::size_of::<u32>(),
            ) != 0
            {
                ext_ok = true;
            }
        }
        (dyn_ok, ext_ok)
    }

    pub fn harden_process(strict_mitigations: bool) -> OsHardeningReport {
        let dumps_suppressed = suppress_crash_dumps();
        let (dynamic_code_prohibited, extension_points_disabled) = if strict_mitigations {
            apply_process_mitigations()
        } else {
            (false, false)
        };
        OsHardeningReport {
            dumps_suppressed,
            dynamic_code_prohibited,
            extension_points_disabled,
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::OsHardeningReport;

    const PR_SET_DUMPABLE: i32 = 4;
    const RLIMIT_CORE: i32 = 4;

    #[repr(C)]
    struct RLimit {
        rlim_cur: u64,
        rlim_max: u64,
    }

    extern "C" {
        fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
        fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    }

    pub fn harden_process(_strict_mitigations: bool) -> OsHardeningReport {
        let mut dump_ok = false;
        let zero_lim = RLimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: Standard Linux prctl/setrlimit syscalls disabling ptrace/core dumps.
        unsafe {
            let p_rc = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
            let r_rc = setrlimit(RLIMIT_CORE, &zero_lim as *const RLimit);
            if p_rc == 0 && r_rc == 0 {
                dump_ok = true;
            }
        }
        OsHardeningReport {
            dumps_suppressed: dump_ok,
            dynamic_code_prohibited: false,
            extension_points_disabled: false,
        }
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
mod platform {
    use super::OsHardeningReport;

    pub fn harden_process(_strict_mitigations: bool) -> OsHardeningReport {
        OsHardeningReport {
            dumps_suppressed: false,
            dynamic_code_prohibited: false,
            extension_points_disabled: false,
        }
    }
}

/// Apply native OS dump suppression and (when `strict_mitigations` is true,
/// e.g. in standalone `secure-transmit --zero-footprint` binaries) irreversible
/// process injection/ACG mitigations.
pub fn harden_process(strict_mitigations: bool) -> OsHardeningReport {
    platform::harden_process(strict_mitigations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_strict_dump_suppression_does_not_panic() {
        // Non-strict avoids locking dynamic code pages inside shared test processes.
        let r = harden_process(false);
        #[cfg(windows)]
        assert!(r.dumps_suppressed);
        let _ = r;
    }
}
