package com.kuru.raspeval.core

import kotlinx.coroutines.Job
import java.lang.IllegalStateException

/**
 * Singleton object that holds the state of the RaspEval framework.
 * This is populated by [RaspEvalBootstrap.init] and is for internal use.
 */
internal object EvalDomainEntity {
    @Volatile
    internal var database: RaspEvalDatabase? = null
    @Volatile
    internal var threatStream: ThreatEventStream? = null
    @Volatile
    internal var orchestrator: AttackOrchestrator? = null
    @Volatile
    internal var threatSubscriberJob: Job? = null

    // --- Safe Getters for internal components ---

    internal fun getDb(): RaspEvalDatabase =
        database ?: throw IllegalStateException(
            "RaspEvalBootstrap.init() must be called before accessing the database."
        )

    internal fun getStream(): ThreatEventStream =
        threatStream ?: throw IllegalStateException(
            "RaspEvalBootstrap.init() must be called before accessing the threat stream."
        )

    internal fun getOrchestrator(): AttackOrchestrator =
        orchestrator ?: throw IllegalStateException(
            "RaspEvalBootstrap.init() must be called before accessing the orchestrator."
        )
}