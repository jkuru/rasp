package com.kuru.raspeval.api

import android.content.Context
import com.kuru.raspeval.core.AttackOrchestrator
import com.kuru.raspeval.core.EvalDomainEntity
import com.kuru.raspeval.core.RaspEvalDatabase
import com.kuru.raspeval.core.ThreatEntity
import com.kuru.raspeval.core.ThreatEventStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Main entry point for the RASP Eval library.
 * The consuming app must call [init] before using the [EvalProvider].
 */
object Bootstrap {

    // This internal scope is for framework-level background tasks,
    // like subscribing to the threat stream.
    private val frameworkScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Initializes all RASP Eval services.
     * This must be called once (e.g., in the Application's onCreate).
     */
    fun init(context: Context) {
        // Prevent double-initialization
        if (EvalDomainEntity.database != null) {
            return
        }

        // 1. Build and store the database instance
        val db = RaspEvalDatabase.getInstance(context.applicationContext)
        EvalDomainEntity.database = db

        // 2. Create and store the event stream
        val stream = ThreatEventStream
        EvalDomainEntity.threatStream = stream

        // 3. Create and store the orchestrator
        val orchestrator = AttackOrchestrator()
        EvalDomainEntity.orchestrator = orchestrator

        // 4. Start the database subscriber
        // This is the logic that was previously in RASPInitProvider
        EvalDomainEntity.threatSubscriberJob = frameworkScope.launch {
            stream.threatJsonFlow.collect { json ->
                db.raspDao().insertThreat(ThreatEntity(threatJson = json))
            }
        }
    }

    /**
     * Shuts down all framework services and clears state.
     */
    fun shutdown() {
        // 1. Stop the database subscriber job
        EvalDomainEntity.threatSubscriberJob?.cancel()

        // 2. Cancel all other framework tasks
        frameworkScope.cancel()

        // 3. Clear all state
        EvalDomainEntity.database = null
        EvalDomainEntity.threatStream = null
        EvalDomainEntity.orchestrator = null
        EvalDomainEntity.threatSubscriberJob = null
    }
}