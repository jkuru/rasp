package com.kuru.raspeval.core

enum class RASPAttackLayer {
    NATIVE_HOOKING,
    RUNTIME_INSTRUMENTATION,
    SYSTEM_CALLS,
    FILE_SYSTEM,
    NETWORK,
    UI,
    MANAGED,
    MANAGED_OS,
    NO_OP_CONFIG,
    WEBVIEW_OS,
}