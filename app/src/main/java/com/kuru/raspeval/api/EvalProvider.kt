package com.kuru.raspeval.api

import android.content.Context
import com.kuru.raspeval.attacks.AttackDefinition
import com.kuru.raspeval.core.AttackResult
import com.kuru.raspeval.core.CorrelatedThreat
import com.kuru.raspeval.core.EvalDomainEntity
import com.kuru.raspeval.core.computeGaps
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch

interface EvalProvider {
    fun initiateAttacks(attacks: List<AttackDefinition>): Flow<AttackResult>

    fun launchAttacks(
        attacks: List<AttackDefinition>,
        collector: suspend (AttackResult) -> Unit
    ): Job

    suspend fun publish(json: String)

    fun correlationResults(): Flow<List<CorrelatedThreat>>

    fun correlationGapCount(): Flow<Int>
}

internal class DefaultEvalProvider(
    private val context: Context,
    private val externalScope: CoroutineScope
) : EvalProvider {
    private val orchestrator get() = EvalDomainEntity.getOrchestrator()
    private val threatStream get() = EvalDomainEntity.getStream()
    private val database get() = EvalDomainEntity.getDb()

    override fun initiateAttacks(attacks: List<AttackDefinition>): Flow<AttackResult> {
        return orchestrator
            .runAttacks(context, attacks)
            .flowOn(Dispatchers.IO)
    }

    override fun launchAttacks(
        attacks: List<AttackDefinition>,
        collector: suspend (AttackResult) -> Unit
    ): Job {
        return externalScope.launch {
            initiateAttacks(attacks).collect(collector)
        }
    }

    override suspend fun publish(json: String) {
        threatStream.publish(json)
    }

    override fun correlationResults(): Flow<List<CorrelatedThreat>> {
        return database.raspDao().getCorrelatedThreats()
    }

    override fun correlationGapCount(): Flow<Int> {
        return correlationResults().computeGaps()
    }
}