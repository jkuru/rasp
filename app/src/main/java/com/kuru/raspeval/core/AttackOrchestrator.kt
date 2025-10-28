package com.kuru.raspeval.core

import android.content.Context
import com.kuru.raspeval.attacks.AttackDefinition
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Internal class that handles the logic of running attack simulations
 * and recording them in the database.
 *
 * It is instantiated by [com.kuru.raspeval.api.Bootstrap] and stored in [EvalDomainEntity].
 * It is used by the [com.kuru.raspeval.RaspEvalProvider].
 */
internal class AttackOrchestrator {

    // Get the DAO from the central domain entity, which was set up by Bootstrap
    private val dao: RaspEvalDao by lazy {
        EvalDomainEntity.getDb().raspDao()
    }

    /**
     * Runs a list of attack simulations sequentially and emits the result for each.
     *
     * @param context The application context.
     * @param attacks The list of [AttackDefinition] objects to execute.
     * @return A [Flow] that emits the [AttackResult] for each attack as it completes.
     */
    fun runAttacks(
        context: Context,
        attacks: List<AttackDefinition>
    ): Flow<AttackResult> = flow {
        // Iterate over the list of attacks
        for (attackDef in attacks) {
            // Run the single attack logic and emit its result
            val result = runSingleAttack(context, attackDef)
            emit(result)
        }
    }

    /**
     * Wraps a single attack lambda with database logging (start/end).
     * This is the core logic for one simulation.
     */
    private suspend fun runSingleAttack(
        context: Context,
        attackDef: AttackDefinition
    ): AttackResult {
        val requirement = attackDef.requirement
        val attackId = requirement.id
        val startTime = System.currentTimeMillis() / 1000

        try {
            // 1. Record attack start
            dao.insertAttack(
                AttackEntity(
                    id = attackId,
                    scenario = requirement.scenario,
                    startTimestamp = startTime
                )
            )

            // 2. Execute pure attack lambda
            attackDef.attack(context)

            // 3. Return Pass if the lambda didn't crash
            return AttackResult.Pass("Attack simulation finished.")

        } catch (e: Exception) {
            // 3b. Return Error if the lambda crashed
            return AttackResult.Error(e)

        } finally {
            // 4. Record attack end time (always)
            val endTime = System.currentTimeMillis() / 1000
            dao.updateAttack(
                AttackEntity(
                    id = attackId,
                    scenario = requirement.scenario,
                    startTimestamp = startTime,
                    endTimestamp = endTime
                )
            )

            // 5. Perform generic cleanup (from your original file)
            // TODO: This should be moved to a specific cleanup lambda in the AttackDefinition
            context.getDir("attack_malware", Context.MODE_PRIVATE)
                .deleteRecursively()
        }
    }
}