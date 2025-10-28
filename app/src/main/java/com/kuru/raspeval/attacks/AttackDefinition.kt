package com.kuru.raspeval.attacks

import android.content.Context
import com.kuru.raspeval.core.AttackRequirement

/**
 * A typealias for the attack lambda function.
 */
typealias AttackLambda = suspend (Context) -> Unit

/**
 * Data class to bundle an attack's metadata (requirement)
 * with its executable logic (lambda).
 */
data class AttackDefinition(
    val requirement: AttackRequirement,
    val attack: AttackLambda
)