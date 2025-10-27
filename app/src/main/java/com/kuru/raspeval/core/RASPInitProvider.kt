package com.kuru.raspeval.core

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class RASPInitProvider : ContentProvider() {
    private val scope = CoroutineScope(Dispatchers.IO)
    private var subscriberJob: Job? = null
    override fun delete(
        p0: Uri,
        p1: String?,
        p2: Array<out String?>?
    ): Int {
        TODO("Not yet implemented")
    }

    override fun getType(p0: Uri): String? {
        TODO("Not yet implemented")
    }

    override fun insert(p0: Uri, p1: ContentValues?): Uri? {
        TODO("Not yet implemented")
    }

    override fun onCreate(): Boolean {
        val db = RaspDatabase.getInstance(context!!)  // Build Room DB
        // No manual table creation—Room handles via entities

        // Start async pub-sub subscriber to insert threats
        subscriberJob = scope.launch {
            RASPThreatPubSub.threatJsonFlow.collect { threatJson ->
                db.raspDao().insertThreat(ThreatEntity(threatJson = threatJson))
            }
        }

        return true
    }

    override fun query(
        p0: Uri,
        p1: Array<out String?>?,
        p2: String?,
        p3: Array<out String?>?,
        p4: String?
    ): Cursor? {
        TODO("Not yet implemented")
    }

    override fun shutdown() {
        subscriberJob?.cancel()
        super.shutdown()
    }

    override fun update(
        p0: Uri,
        p1: ContentValues?,
        p2: String?,
        p3: Array<out String?>?
    ): Int {
        TODO("Not yet implemented")
    }

}