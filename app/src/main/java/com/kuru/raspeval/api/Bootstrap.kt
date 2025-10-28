package com.kuru.raspeval.api

import android.content.Context
import android.util.Log
import com.kuru.raspeval.core.AttackOrchestrator
import com.kuru.raspeval.core.EvalDomainEntity
import com.kuru.raspeval.core.RaspEvalDatabase
import com.kuru.raspeval.core.ThreatEntity
import com.kuru.raspeval.core.ThreatEventStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch

/**
 * Main entry point for the RASP Eval library.
 * The consuming app must call [init] before using the [EvalProvider].
 */
internal object Bootstrap {

    private const val TAG = "RaspEval"
    private const val RETRY_DELAY_MILLIS = 1_000L

    private val scopeLock = Any()
    @Volatile
    private var frameworkScope: CoroutineScope? = null

    private fun createFrameworkScope(): CoroutineScope =
        CoroutineScope(Dispatchers.IO + SupervisorJob())

    private fun currentScope(): CoroutineScope {
        val existing = frameworkScope
        val isActive = existing?.coroutineContext?.job?.isActive == true
        if (isActive && existing != null) {
            return existing
        }
        return createFrameworkScope().also { frameworkScope = it }
    }

    /**
     * Initializes all RASP Eval services.
     * This must be called once (e.g., in the Application's onCreate).
     */
    fun init(context: Context) {
        synchronized(scopeLock) {
            if (EvalDomainEntity.database != null) {
                return
            }

            val db = RaspEvalDatabase.getInstance(context.applicationContext)
            val stream = ThreatEventStream
            val orchestrator = AttackOrchestrator()
            val scope = currentScope()

            val subscriberJob = scope.launch {
                while (isActive) {
                    try {
                        stream.threatJsonFlow.collect { json ->
                            db.raspDao().insertThreat(ThreatEntity(threatJson = json))
                        }
                    } catch (cancellation: CancellationException) {
                        throw cancellation
                    } catch (throwable: Throwable) {
                        Log.e(TAG, "Threat ingestion failed, retrying", throwable)
                        delay(RETRY_DELAY_MILLIS)
                    }
                }
            }

            EvalDomainEntity.install(db, stream, orchestrator, subscriberJob)

            Log.i(TAG, "RaspEval bootstrap complete")
        }
    }

    /**
     * Shuts down all framework services and clears state.
     */
    fun shutdown() {
        synchronized(scopeLock) {
            EvalDomainEntity.threatSubscriberJob?.cancel()
            frameworkScope?.cancel()
            frameworkScope = null
            EvalDomainEntity.clear()

            Log.i(TAG, "RaspEval shutdown complete")
        }
    }
}