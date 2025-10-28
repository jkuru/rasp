package com.kuru.raspeval.api

import android.content.Context
import kotlinx.coroutines.CoroutineScope

object RaspEval {
    fun init(context: Context) {
        Bootstrap.init(context.applicationContext)
    }

    fun shutdown() {
        Bootstrap.shutdown()
    }

    fun provider(
        context: Context,
        externalScope: CoroutineScope
    ): EvalProvider {
        return DefaultEvalProvider(context.applicationContext, externalScope)
    }
}
