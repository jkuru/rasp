package com.kuru.raspeval.tests.examples

import android.content.Context
import com.kuru.raspeval.core.NativeTestCase
import com.kuru.raspeval.core.Priority
import com.kuru.raspeval.core.TestLayer
import com.kuru.raspeval.core.TestRequirement
import com.kuru.raspeval.core.TestResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Concrete implementation for Test #55: Low-Level Native Call Interception
 * This test attempts to mprotect the PLT page for a symbol to simulate GOT/PLT hooking.
 * A RASP solution should block this.
 */
class Test_55_LowLevelNativeCallInterception : NativeTestCase() {
    override val requirement = TestRequirement(
        id = "55",
        group = "Group 6",
        scenario = "Low-Level Native Call Interception",
        priority = Priority.P1,
        layer = TestLayer.NATIVE_HOOKING
    )

    override suspend fun execute(context: Context): TestResult = withContext(Dispatchers.IO) {
        try {
            // Attempt to hook 'open' in libc.so
            val libName = "libc.so"
            val symbolName = "open"
            val resultCode = attemptGotHook(libName, symbolName)
            if (resultCode == 0) {
                // mprotect succeeded
                TestResult.Fail(
                    reason = "Attack Succeeded: PLT page made writable.",
                    details = "The native 'attemptGotHook' function returned 0, indicating RASP did not block the hooking attempt."
                )
            } else {
                // mprotect failed
                TestResult.Pass(
                    message = "Attack Blocked: PLT page protection change failed with code $resultCode."
                )
            }
        } catch (e: Exception) {
            TestResult.Error(e)
        }
    }
}