package com.kuru.raspeval.core

data class AttackRequirement(
    val id: String,
    val group: String,
    val scenario: String,
    val priority: AttackPriority,
    val layer: AttackLayer
)