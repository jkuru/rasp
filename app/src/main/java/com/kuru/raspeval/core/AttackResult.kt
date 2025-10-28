package com.kuru.raspeval.core

sealed class AttackResult {
    data class Pass(val message: String) : AttackResult()
    data class Fail(val reason: String, val details: String? = null) : AttackResult()
    data class Skipped(val reason: String) : AttackResult()
    data class Error(val exception: Throwable) : AttackResult()
}