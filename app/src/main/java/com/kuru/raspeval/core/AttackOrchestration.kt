package com.kuru.raspeval.core

import android.content.Context

class AttackOrchestration {

    // Runner function to wrap attack execution (handles DB recording, cleanup, result)
    suspend fun runAttack(
        context: Context,
        requirement: RASPAttackRequirement,
        attackFunction: suspend (Context) -> Unit  // Lambda type: pure attack sim
    ): RASPAttackResult {
        val db = RaspDatabase.getInstance(context)
        val dao = db.raspDao()
        val attackId = requirement.id
        val startTime = System.currentTimeMillis() / 1000
        try {
            // Record start
            dao.insertAttack(
                AttackEntity(
                    id = attackId,
                    scenario = requirement.scenario,
                    startTimestamp = startTime
                )
            )

            // Execute pure attack lambda
            attackFunction(context)

            return RASPAttackResult.Pass("Attack simulated")
        } catch (e: Exception) {
            return RASPAttackResult.Error(e)
        } finally {
            // Record end and cleanup (e.g., for file-based attacks)
            val endTime = System.currentTimeMillis() / 1000
            dao.updateAttack(
                AttackEntity(
                    id = attackId,
                    scenario = requirement.scenario,
                    startTimestamp = startTime,
                    endTimestamp = endTime
                )
            )
            context.getDir("attack_malware", Context.MODE_PRIVATE)
                .deleteRecursively()  // Adapt per attack if needed
        }
    }
}