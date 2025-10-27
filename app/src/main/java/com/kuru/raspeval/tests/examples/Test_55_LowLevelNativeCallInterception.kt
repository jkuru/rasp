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
 * Concrete implementation for Test #55: Low-Level Native Call Interception
 * This test attempts to mprotect the PLT page for a symbol to simulate GOT/PLT hooking.
 * A RASP solution should block this.
 */
class Test_55_LowLevelNativeCallInterception : NativeTestCase() {
    override val requirement = RASPAttackRequirement(
        id = "55",
        group = "Group 6",
        scenario = "Low-Level Native Call Interception",
        RASPPriority = RASPPriority.P1,
        layer = RASPAttackLayer.NATIVE_HOOKING
    )

    override suspend fun execute(context: Context): RASPAttackResult = withContext(Dispatchers.IO) {
        try {
            // Attempt to hook 'open' in libc.so
            val libName = "libc.so"
            val symbolName = "open"
            val resultCode = attemptGotHook(libName, symbolName)
            if (resultCode == 0) {
                // mprotect succeeded
                RASPAttackResult.Fail(
                    reason = "Attack Succeeded: PLT page made writable.",
                    details = "The native 'attemptGotHook' function returned 0, indicating RASP did not block the hooking attempt."
                )
            } else {
                // mprotect failed
                RASPAttackResult.Pass(
                    message = "Attack Blocked: PLT page protection change failed with code $resultCode."
                )
            }
        } catch (e: Exception) {
            RASPAttackResult.Error(e)
        }
    }
}