package com.kuru.raspeval.core


/**
 * Singleton object that loads the Rust attack library ("rasp_attack_harness")
 * and provides the JNI-to-Rust function calls for all native attacks.
 */
object NativeAttackHarness {
    // Load the Rust 'attack' library
    init {
        System.loadLibrary("rasp_attack_harness")
        nativeInit() // Initialize the native logger
    }

    // JNI function to init native logger
    @JvmStatic
    external fun nativeInit()

    // Test #3: Zygote/Ptrace
    @JvmStatic
    external fun attemptPtrace(pid: Int): Int

    // Test #55: Low-Level Native Call Interception
    @JvmStatic
    external fun attemptGotHook(libName: String, symbolName: String): Int

    // Test #13: Runtime Code Injection Halt
    @JvmStatic
    external fun triggerNativeMemoryWrite(address: Long): Int

    // Test #4: Frida/Xposed Detection
    @JvmStatic
    external fun isFridaXposedDetected(): Boolean
}