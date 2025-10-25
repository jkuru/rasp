package com.kuru.raspeval.core


import android.content.Context
/**
 * Sealed interface for all RASP evaluation test cases.
 * This structure forces a test to declare if it's a
 * Managed (Kotlin) or Native (Rust/JNI) test.
 */
sealed interface RaspTestCase {
    /**
     * The requirement metadata this test case validates.
     */
    val requirement: TestRequirement
    /**
     * Executes the test logic.
     * @param context The Android Context, needed for most tests.
     * @return A [TestResult] (Pass, Fail, Skipped, Error).
     */
    suspend fun execute(context: Context): TestResult
}
/**
 * A base class for tests that operate purely in the
 * Managed (Kotlin/Java) layer.
 * e.g., Faking intents, checking permissions, querying WindowManager.
 */
abstract class ManagedTestCase : RaspTestCase {
    // You can add shared helper functions here
    fun isServiceRunning(context: Context, serviceClass: Class<*>): Boolean {
        // Implementation logic...
        return false
    }
}
/**
 * A base class for tests that must trigger native code
 * to simulate an attack.
 * e.g., ptrace, GOT/PLT hooking, JNI exploits.
 */
abstract class NativeTestCase : RaspTestCase {
    companion object {
        // Load the Rust 'attack' library
        init {
            System.loadLibrary("rasp_attack_harness")
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
    // Call the init once
    init {
        nativeInit()
    }
}