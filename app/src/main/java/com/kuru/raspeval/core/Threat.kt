package com.kuru.raspeval.core

import kotlinx.serialization.Serializable

/**
 * Generic data class for threats, vendor-agnostic (dev-only).
 */
@Serializable
data class Threat(
    val id: Int,
    val name: String,
    val severity: String,
    val details: String? = null
)
