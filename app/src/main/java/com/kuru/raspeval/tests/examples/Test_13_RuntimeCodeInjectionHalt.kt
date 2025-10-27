package com.kuru.raspeval.tests.examples


import android.content.Context
import com.kuru.raspeval.core.NativeTestCase
import com.kuru.raspeval.core.RASPPriority
import com.kuru.raspeval.core.RASPAttackLayer
import com.kuru.raspeval.core.RASPAttackRequirement
import com.kuru.raspeval.core.RASPAttackResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Concrete implementation for Test #13: Runtime Code Injection Halt
 * This test attempts to write to a protected memory address to simulate code injection.
 * A RASP solution should detect this and halt execution.
 */
class Test_13_RuntimeCodeInjectionHalt : NativeTestCase() {
    override val requirement = RASPAttackRequirement(
        id = "13",
        group = "Group 2",
        scenario = "Runtime Code Injection Halt",
        RASPPriority = RASPPriority.P1,
        layer = RASPAttackLayer.NATIVE_HOOKING
    )

    override suspend fun execute(context: Context): RASPAttackResult = withContext(Dispatchers.IO) {
        try {
            // Attempt to write to address 0x0 (invalid)
            val address: Long = 0x0
            val resultCode = triggerNativeMemoryWrite(address)
            if (resultCode == 0) {
                // Write succeeded
                RASPAttackResult.Fail(
                    reason = "Attack Succeeded: memory write completed.",
                    details = "The native 'triggerNativeMemoryWrite' function returned 0, indicating RASP did not block the injection attempt."
                )
            } else {
                // Write failed (segfault caught)
                RASPAttackResult.Pass(
                    message = "Attack Blocked: memory write failed with code $resultCode."
                )
            }
        } catch (e: Exception) {
            RASPAttackResult.Error(e)
        }
    }
}