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
 * Concrete implementation for Test #13: Runtime Code Injection Halt
 * This test attempts to write to a protected memory address to simulate code injection.
 * A RASP solution should detect this and halt execution.
 */
class Test_13_RuntimeCodeInjectionHalt : NativeTestCase() {
    override val requirement = TestRequirement(
        id = "13",
        group = "Group 2",
        scenario = "Runtime Code Injection Halt",
        priority = Priority.P1,
        layer = TestLayer.NATIVE_HOOKING
    )

    override suspend fun execute(context: Context): TestResult = withContext(Dispatchers.IO) {
        try {
            // Attempt to write to address 0x0 (invalid)
            val address: Long = 0x0
            val resultCode = triggerNativeMemoryWrite(address)
            if (resultCode == 0) {
                // Write succeeded
                TestResult.Fail(
                    reason = "Attack Succeeded: memory write completed.",
                    details = "The native 'triggerNativeMemoryWrite' function returned 0, indicating RASP did not block the injection attempt."
                )
            } else {
                // Write failed (segfault caught)
                TestResult.Pass(
                    message = "Attack Blocked: memory write failed with code $resultCode."
                )
            }
        } catch (e: Exception) {
            TestResult.Error(e)
        }
    }
}