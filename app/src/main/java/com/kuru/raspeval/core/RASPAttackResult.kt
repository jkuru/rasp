package com.kuru.raspeval.core

sealed class RASPAttackResult {
    data class Pass(val message: String) : RASPAttackResult()
    data class Fail(val reason: String, val details: String? = null) : RASPAttackResult()
    data class Skipped(val reason: String) : RASPAttackResult()
    data class Error(val exception: Throwable) : RASPAttackResult()
}