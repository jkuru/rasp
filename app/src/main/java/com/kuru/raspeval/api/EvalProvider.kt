package com.kuru.raspeval.api

import android.content.Context
import com.kuru.raspeval.attacks.AttackDefinition
import com.kuru.raspeval.core.CorrelatedThreat
import com.kuru.raspeval.core.EvalDomainEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * Public API for the RASP Eval framework.
 *
 * @param context The application context.
 * @param externalScope The CoroutineScope from the consuming app, used to launch attacks.
 */
class EvalProvider(
    private val context: Context,
    private val externalScope: CoroutineScope
) {
    private val orchestrator = EvalDomainEntity.getOrchestrator()
    private val threatStream = EvalDomainEntity.getStream()
    private val database = EvalDomainEntity.getDb()

    /**
     * API 1: Initiates a list of attack simulations.
     * Attacks are run sequentially in a coroutine on the [externalScope].
     *
     * @param attacks A list of [com.kuru.raspeval.attacks.AttackDefinition] objects to execute.
     * @return A [kotlinx.coroutines.flow.Flow] that emits the result of each simulation as it completes.
     */
    fun initiateAttacks(attacks: List<AttackDefinition>) {
        externalScope.launch {
            orchestrator.runAttacks(context, attacks).collect { result ->
                //TODO Handle results
            }
        }
    }

    /**
     * API 2: Publishes a threat JSON from the RASP vendor.
     * This is called by the app's listener (e.g., from Zimperium).
     *
     * @param json The JSON string of the threat to publish.
     */
    suspend fun publish(json: String) {
        threatStream.publish(json)
    }

    /**
     * API 3: The streaming interface for correlation results.
     * The app can collect this flow to get live updates from the database.
     *
     * @return A Flow that emits the list of all correlated attack/threat pairs.
     */
    fun getCorrelationResults(): Flow<List<CorrelatedThreat>> {
        return database.raspDao().getCorrelatedThreats()
    }

    /**
     * Helper extension function for the app to compute detection gaps from the results flow.
     *
     * @return A Flow that emits only the count of attacks that have no matching threat.
     */
    fun Flow<List<CorrelatedThreat>>.computeGaps(): Flow<Int> = map { results ->
        results.count { it.threatJson == null }
    }
}