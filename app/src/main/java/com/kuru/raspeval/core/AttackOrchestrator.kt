package com.kuru.raspeval.core

import android.content.Context
import com.kuru.raspeval.attacks.AttackDefinition
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext

/**
 * Internal class that handles the logic of running attack simulations
 * and recording them in the database.
 *
 * It is instantiated by [com.kuru.raspeval.api.Bootstrap] and stored in [EvalDomainEntity].
 * It is used by the [com.kuru.raspeval.api.EvalProvider].
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
    ): Flow<AttackResult> =
        flow {
            for (attackDef in attacks) {
                val result = runSingleAttack(context, attackDef)
                emit(result)
            }
        }.flowOn(Dispatchers.IO)

    /**
     * Wraps a single attack lambda with database logging (start/end).
     * This is the core logic for one simulation.
     */
    private suspend fun runSingleAttack(
        context: Context,
        attackDef: AttackDefinition
    ): AttackResult = withContext(Dispatchers.IO) {
        val requirement = attackDef.requirement
        val attackId = requirement.id
        val startTime = System.currentTimeMillis() / 1000

        try {
            dao.insertAttack(
                AttackEntity(
                    id = attackId,
                    scenario = requirement.scenario,
                    startTimestamp = startTime
                )
            )

            attackDef.attack(context)

            AttackResult.Pass("Attack simulation finished.")
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (e: Exception) {
            AttackResult.Error(e)
        } finally {
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
                .deleteRecursively()
        }
    }
}