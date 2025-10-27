package com.kuru.raspeval.core

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Generic data class for threats, vendor-agnostic (internal to framework).
 */
@Serializable
data class RASPThreat(
    val id: Int,
    val name: String,
    val severity: String,
    val details: String? = null
)

/**
 * Singleton object for pub-sub of threat events as JSON (vendor-agnostic).
 * Main app publishes JSON; framework subscribes and deserializes internally.
 */
object RASPThreatPubSub {
    private val _threatJsonFlow = MutableSharedFlow<String>(replay = 1)  // JSON strings
    val threatJsonFlow = _threatJsonFlow.asSharedFlow()

    /**
     * Publish a threat as JSON string from the main app (vendor-specific code stays in app).
     * @param json The JSON string of the serialized threat to emit.
     */
    suspend fun publish(json: String) {
        _threatJsonFlow.emit(json)
    }

    /**
     * Helper to deserialize JSON to RASPThreat (used internally in tests/framework only).
     */
    internal fun deserialize(json: String): RASPThreat {
        return Json.decodeFromString<RASPThreat>(json)
    }
}