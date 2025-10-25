use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jboolean};
use jni::JNIEnv;
// Import the ptrace function from the 'nix' crate
use nix::sys::ptrace;
use nix::unistd::Pid;
use android_log::{Config, Level, log};
// For file and dir reading
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
// For GOT hook
use plt_rs::{DynamicLibrary, find_executable, find_library, LibraryEntry};
use anyhow::{anyhow, Result};
// For libc types
use libc::{c_void, c_int, c_char, sa_handler_t, sigaction, sigemptyset, sigjmp_buf, sigsetjmp, siglongjmp, SIGSEGV};
// Macro for logging
macro_rules! log_info {
    ($($arg:tt)*) => {{
        log(Level::Info, "RustAttackHarness", &format!($($arg)*));
    }};
}
macro_rules! log_err {
    ($($arg:tt)*) => {{
        log(Level::Error, "RustAttackHarness", &format!($($arg)*));
    }};
}
// Initialize logging
#[no_mangle]
pub extern "system" fn Java_com_raspeval_core_NativeTestCase_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
) {
    android_log::init(Config::default().with_min_level(Level::Trace)).unwrap_or_default();
    log_info!("Rust Native Harness Initialized");
}
///
/// This is the Rust function that Kotlin will call for Test #3.
/// The name *must* match the Java/Kotlin package and class path.
///
#[no_mangle]
pub extern "system" fn Java_com_raspeval_core_NativeTestCase_attemptPtrace(
    mut env: JNIEnv,
    _class: JClass,
    pid: jint,
) -> jint {
    log_info!("Attempting ptrace on PID: {}", pid);
    // This is the "attack"
    let target_pid = Pid::from_raw(pid);
    // We can use PTRACE_TRACEME, but ATTACH is more common for debuggers
    match ptrace::attach(target_pid) {
        Ok(_) => {
            log_err!("ptrace attach Succeeded! RASP may be bypassed.");
            // Attack Succeeded. Detach immediately.
            let _ = ptrace::detach(target_pid, None);
            0 // Return 0 for success
        }
        Err(e) => {
            log_info!("ptrace attach failed (AS EXPECTED). RASP Blocked: {}", e);
            // Attack failed (hopefully blocked by RASP)
            -1 // Return -1 for failure
        }
    }
}
///
/// JNI function for Test #55 (GOT/PLT Hooking)
///
#[no_mangle]
pub extern "system" fn Java_com_raspeval_core_NativeTestCase_attemptGotHook(
    mut env: JNIEnv,
    _class: JClass,
    lib_name: JString,
    symbol_name: JString,
) -> jint {
    let lib_str: String = env.get_string(&lib_name).expect("Couldn't get lib name").into();
    let sym_str: String = env.get_string(&symbol_name).expect("Couldn't get symbol name").into();
    log_info!("Attempting GOT/PLT hook on symbol '{}' in lib '{}'", sym_str, lib_str);
    // Try to make the PLT page writable - if succeeds, means can hook (bypass), else blocked
    if let Ok(()) = attempt_mprotect_plt(&lib_str, &sym_str) {
        log_err!("mprotect succeeded! RASP may be bypassed.");
        0 // Success (bypass)
    } else {
        log_info!("mprotect failed (AS EXPECTED). RASP Blocked.");
        -1 // Failure (blocked)
    }
}
fn attempt_mprotect_plt(lib_str: &str, sym_str: &str) -> Result<()> {
    let entry: LibraryEntry = if lib_str == "executable" {
        find_executable().ok_or(anyhow!("unable to find target executable"))?
    } else {
        find_library(lib_str).ok_or(anyhow!("unable to find library {}", lib_str))?
    };
    let dyn_lib = DynamicLibrary::initialize(entry)?;
    let target_function = dyn_lib.try_find_function(sym_str).ok_or(anyhow!("unable to find symbol {}", sym_str))?;
    let base_addr = dyn_lib.library().addr();
    let plt_fn_ptr = (base_addr + target_function.r_offset as usize) as *mut *mut c_void;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize };
    let plt_page = ((plt_fn_ptr as usize / page_size) * page_size) as *mut c_void;
    let prot_res = unsafe { libc::mprotect(plt_page, page_size, libc::PROT_WRITE | libc::PROT_READ) };
    if prot_res != 0 {
        return Err(anyhow!("mprotect to rw failed with {}", prot_res));
    }
    // Success, revert
    let prot_res_back = unsafe { libc::mprotect(plt_page, page_size, libc::PROT_READ) };
    if prot_res_back != 0 {
        return Err(anyhow!("mprotect back to r failed with {}", prot_res_back));
    }
    Ok(())
}
///
/// JNI function for Test #13 (Runtime Code Injection)
///
#[no_mangle]
pub extern "system" fn Java_com_raspeval_core_NativeTestCase_triggerNativeMemoryWrite(
    mut env: JNIEnv,
    _class: JClass,
    address: jlong,
) -> jint {
    log_info!("Attempting to write to protected memory address: 0x{:X}", address);
    static mut JMP_BUF: sigjmp_buf = [0i32; 128]; // Approximate size, adjust based on platform
    unsafe extern "C" fn handler(_sig: c_int) {
        log_info!("Caught SIGSEGV");
        siglongjmp(&mut JMP_BUF, 1);
    }
    let mut old_sa: sigaction = unsafe { std::mem::zeroed() };
    let mut sa: sigaction = unsafe { std::mem::zeroed() };
    sa.sa_handler = handler as sa_handler_t;
    unsafe { sigemptyset(&mut sa.sa_mask) };
    sa.sa_flags = 0;
    unsafe { sigaction(SIGSEGV, &sa, &mut old_sa) };
    if unsafe { sigsetjmp(&mut JMP_BUF, 1) } == 0 {
        // Attempt write
        let ptr = address as *mut u8;
        unsafe { *ptr = 0x90 };
        log_err!("Write Succeeded! RASP may be bypassed.");
        unsafe { sigaction(SIGSEGV, &old_sa, std::ptr::null_mut()) };
        0 // Success
    } else {
        log_info!("Write failed (Caught Signal). This may be RASP or OS.");
        unsafe { sigaction(SIGSEGV, &old_sa, std::ptr::null_mut()) };
        -1 // Failure
    }
}
///
/// Helper functions for Frida/Xposed detection
///
fn check_maps_for_instrumentation() -> bool {
    if let Ok(file) = File::open("/proc/self/maps") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                let lower = l.to_lowercase();
                if lower.contains("frida") || lower.contains("xposed") {
                    return true;
                }
            }
        }
    }
    false
}

fn check_threads_for_instrumentation() -> bool {
    if let Ok(entries) = fs::read_dir("/proc/self/task") {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = format!("{}/comm", entry.path().display());
                if let Ok(content) = fs::read_to_string(&path) {
                    let lower = content.to_lowercase();
                    if lower.contains("frida") || lower.contains("xposed") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_instrumentation_detected() -> bool {
    check_maps_for_instrumentation() || check_threads_for_instrumentation()
}

///
/// JNI function for Test #4 (Frida/Xposed Detection)
///
#[no_mangle]
pub extern "system" fn Java_com_raspeval_core_NativeTestCase_isFridaXposedDetected(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if is_instrumentation_detected() {
        log_err!("Dynamic instrumentation (Frida/Xposed) detected!");
        1 as jboolean // True
    } else {
        log_info!("No dynamic instrumentation detected.");
        0 as jboolean // False
    }
}