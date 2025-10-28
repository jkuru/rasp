package com.kuru.raspeval.core


/**
 * Singleton object that loads the Rust attack library ("rasp_attack_harness")
 * and provides the JNI-to-Rust function calls for all native attacks.
 */
object NativeAttackHarness {
    private val libraryLoader = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        System.loadLibrary("rasp_attack_harness")
        nativeInit()
    }

    private fun ensureLoaded() {
        runCatching { libraryLoader.value }
            .getOrElse { throwable ->
                throw IllegalStateException(
                    "Failed to load rasp_attack_harness native library.",
                    throwable
                )
            }
    }

    // JNI function to init native logger
    @JvmStatic
    private external fun nativeInit()

    // Test #3: Zygote/Ptrace
    @JvmStatic
    fun attemptPtrace(pid: Int): Int {
        ensureLoaded()
        return nativeAttemptPtrace(pid)
    }

    // Test #55: Low-Level Native Call Interception
    @JvmStatic
    fun attemptGotHook(libName: String, symbolName: String): Int {
        ensureLoaded()
        return nativeAttemptGotHook(libName, symbolName)
    }

    // Test #13: Runtime Code Injection Halt
    @JvmStatic
    fun triggerNativeMemoryWrite(address: Long): Int {
        ensureLoaded()
        return nativeTriggerNativeMemoryWrite(address)
    }

    // Test #4: Frida/Xposed Detection
    @JvmStatic
    fun isFridaXposedDetected(): Boolean {
        ensureLoaded()
        return nativeIsFridaXposedDetected()
    }

    @JvmStatic
    private external fun nativeAttemptPtrace(pid: Int): Int

    @JvmStatic
    private external fun nativeAttemptGotHook(libName: String, symbolName: String): Int

    @JvmStatic
    private external fun nativeTriggerNativeMemoryWrite(address: Long): Int

    @JvmStatic
    private external fun nativeIsFridaXposedDetected(): Boolean
}