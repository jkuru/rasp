package com.kuru.raspeval.core

data class RASPAttackRequirement(
    val id: String,
    val group: String,
    val scenario: String,
    val RASPPriority: RASPPriority,
    val layer: RASPAttackLayer
)