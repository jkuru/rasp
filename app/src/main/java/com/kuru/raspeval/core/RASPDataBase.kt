package com.kuru.raspeval.core

import android.content.Context
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow
import androidx.room.Database
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.map

@Entity(tableName = "attacks")
data class AttackEntity(
    @PrimaryKey val id: String,  // e.g., requirement.id
    val scenario: String,
    val startTimestamp: Long,
    val endTimestamp: Long? = null  // Nullable until attack done
)

@Entity(tableName = "threats")
data class ThreatEntity(
    @PrimaryKey(autoGenerate = true) val dbId: Int = 0,
    val threatJson: String,
    val timestamp: Long = System.currentTimeMillis() / 1000
)


@Dao
interface RaspDao {
    // Insert attack start
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAttack(attack: AttackEntity)

    // Update attack end
    @Update
    suspend fun updateAttack(attack: AttackEntity)

    // Insert threat (from pub-sub)
    @Insert
    suspend fun insertThreat(threat: ThreatEntity)

    // Reactive query for correlated threats (joins attacks and threats via time window)
    @Query("""
        SELECT a.id AS attack_id, t.threat_json
        FROM attacks a
        LEFT JOIN threats t ON t.timestamp BETWEEN a.startTimestamp AND COALESCE(a.endTimestamp, a.startTimestamp + 60)  -- 60s post-attack window
        ORDER BY a.startTimestamp DESC
    """)
    fun getCorrelatedThreats(): Flow<List<CorrelatedThreat>>  // Flow for reactive streaming
}

// Result class (for Flow emission)
data class CorrelatedThreat(val attackId: String, val threatJson: String?)


@Database(entities = [AttackEntity::class, ThreatEntity::class], version = 1, exportSchema = false)
abstract class RaspDatabase : RoomDatabase() {
    abstract fun raspDao(): RaspDao

    companion object {
        @Volatile private var INSTANCE: RaspDatabase? = null

        fun getInstance(context: Context): RaspDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: androidx.room.Room.databaseBuilder(
                    context.applicationContext,
                    RaspDatabase::class.java,
                    "rasp_threats.db"
                ).build().also { INSTANCE = it }
            }
        }
    }
}

// Stream correlated threats reactively
fun streamCorrelatedThreats(context: Context): Flow<List<CorrelatedThreat>> {
    val dao = RaspDatabase.getInstance(context).raspDao()
    return dao.getCorrelatedThreats()
}

// Compute gaps from flow (e.g., in collector)
fun Flow<List<CorrelatedThreat>>.computeGaps(): Flow<Int> = map { results ->
    results.count { it.threatJson == null }
}