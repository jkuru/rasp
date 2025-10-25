package com.kuru.raspeval.core

sealed class TestResult {
    data class Pass(val message: String) : TestResult()
    data class Fail(val reason: String, val details: String? = null) : TestResult()
    data class Skipped(val reason: String) : TestResult()
    data class Error(val exception: Throwable) : TestResult()
}