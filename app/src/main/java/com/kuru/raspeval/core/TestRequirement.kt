package com.kuru.raspeval.core

data class TestRequirement(
    val id: String,
    val group: String,
    val scenario: String,
    val priority: Priority,
    val layer: TestLayer
)