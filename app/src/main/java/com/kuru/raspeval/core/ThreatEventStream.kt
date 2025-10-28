package com.kuru.raspeval.core

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.serialization.json.Json

/**
 * Singleton object for pub-sub of threat events (as JSON).
 * Replaces RASPThreatPubSub.
 */
internal object ThreatEventStream {
    private val _threatJsonFlow = MutableSharedFlow<String>(replay = 1)
    val threatJsonFlow = _threatJsonFlow.asSharedFlow()

    /**
     * Publishes a threat as JSON string.
     * Called by the RaspEvalProvider.
     */
    suspend fun publish(json: String) {
        _threatJsonFlow.emit(json)
    }

    /**
     * Helper to deserialize JSON (used internally if needed).
     */
    internal fun deserialize(json: String): Threat {
        return Json.decodeFromString<Threat>(json)
    }
}