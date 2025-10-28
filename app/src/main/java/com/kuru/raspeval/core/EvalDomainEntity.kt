package com.kuru.raspeval.core

import kotlinx.coroutines.Job
import java.lang.IllegalStateException

/**
 * Singleton object that holds the state of the RaspEval framework.
 * This is populated by [com.kuru.raspeval.api.Bootstrap.init] and is for internal use.
 */
internal object EvalDomainEntity {
    @Volatile
    internal var database: RaspEvalDatabase? = null
        private set
    @Volatile
    internal var threatStream: ThreatEventStream? = null
        private set
    @Volatile
    internal var orchestrator: AttackOrchestrator? = null
        private set
    @Volatile
    internal var threatSubscriberJob: Job? = null
        private set

    @Synchronized
    internal fun install(
        database: RaspEvalDatabase,
        stream: ThreatEventStream,
        orchestrator: AttackOrchestrator,
        subscriberJob: Job
    ) {
        this.database = database
        this.threatStream = stream
        this.orchestrator = orchestrator
        this.threatSubscriberJob = subscriberJob
    }

    @Synchronized
    internal fun clear() {
        database = null
        threatStream = null
        orchestrator = null
        threatSubscriberJob = null
    }

    // --- Safe Getters for internal components ---

    internal fun getDb(): RaspEvalDatabase =
        database ?: throw IllegalStateException(
            "RaspEval.init() must be called before accessing the database."
        )

    internal fun getStream(): ThreatEventStream =
        threatStream ?: throw IllegalStateException(
            "RaspEval.init() must be called before accessing the threat stream."
        )

    internal fun getOrchestrator(): AttackOrchestrator =
        orchestrator ?: throw IllegalStateException(
            "RaspEval.init() must be called before accessing the orchestrator."
        )
}
