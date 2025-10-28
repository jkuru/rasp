package com.kuru.raspeval.attacks


import android.content.Context
import com.kuru.raspeval.core.AttackLayer
import com.kuru.raspeval.core.AttackPriority
import com.kuru.raspeval.core.AttackRequirement
import com.kuru.raspeval.core.NativeAttackHarness
import java.io.File

/**
 * A collection of sample attack definitions.
 * The consuming app can create a list of these to pass to [RaspEvalProvider.initiateAttacks].
 */
object ExampleAttacks {


    // Example 1: Managed file-system attack
    val offlineMalwareAttack = AttackDefinition(
        requirement = AttackRequirement(
            id = "1",
            group = "Group 1",
            scenario = "Offline Malware Scan",
            priority = AttackPriority.P2,
            layer = AttackLayer.MANAGED_OS
        ),
        attack = { context ->
            val attackDir = context.getDir("attack_malware", Context.MODE_PRIVATE)
            val maliciousFile = File(attackDir, "dummy_malicious.pdf")
            if (!maliciousFile.exists()) {
                maliciousFile.createNewFile()
                maliciousFile.writeText("MALICIOUS_PAYLOAD_SIMULATION")
            }
        }
    )

    // Example 2: Native ptrace attack
    val ptraceAttack = AttackDefinition(
        requirement = AttackRequirement(
            id = "3",
            group = "Group 1",
            scenario = "Zygote/Ptrace Detection",
            priority = AttackPriority.P1,
            layer = AttackLayer.NATIVE_HOOKING
        ),
        attack = {
            // Call the JNI function from our harness
            val resultCode = NativeAttackHarness.attemptPtrace(android.os.Process.myPid())
            if (resultCode == 0) {
                // The attack *simulation* succeeded (ptrace was allowed).
                // The framework will determine if this is a "gap" by checking
                // the database for a corresponding threat.
            }
        }
    )

    // Example 3: Native GOT hook attack
    val gotHookAttack = AttackDefinition(
        requirement = AttackRequirement(
            id = "55",
            group = "Group 6",
            scenario = "Native Call Interception",
            priority = AttackPriority.P1,
            layer = AttackLayer.NATIVE_HOOKING
        ),
        attack = {
            val resultCode = NativeAttackHarness.attemptGotHook("libc.so", "open")
            if (resultCode == 0) {
                // mprotect succeeded, hook was possible.
            }
        }
    )

    val allAttacks = listOf(
        offlineMalwareAttack,
        ptraceAttack,
        gotHookAttack
    )
}