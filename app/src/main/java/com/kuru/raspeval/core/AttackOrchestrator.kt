package com.kuru.raspeval.core

import android.content.Context
import androidx.room.*
import kotlinx.coroutines.flow.Flow

// --- Entities (No Change) ---
@Entity(tableName = "attacks")
data class AttackEntity(
    @PrimaryKey val id: String,
    val scenario: String,
    val startTimestamp: Long,
    val endTimestamp: Long? = null
)

@Entity(tableName = "threats")
data class ThreatEntity(
    @PrimaryKey(autoGenerate = true) val dbId: Int = 0,
    val threatJson: String,
    val timestamp: Long = System.currentTimeMillis() / 1000
)

// --- Result Class (No Change) ---
data class CorrelatedThreat(val attackId: String, val threatJson: String?)

// --- DAO (Renamed) ---
@Dao
interface RaspEvalDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAttack(attack: AttackEntity)

    @Update
    suspend fun updateAttack(attack: AttackEntity)

    @Insert
    suspend fun insertThreat(threat: ThreatEntity)

    /**
     * This is the main reactive query for correlation.
     * It's consumed by the RaspEvalProvider.
     */
    @Query("""
        SELECT a.id AS attack_id, t.threat_json
        FROM attacks a
        LEFT JOIN threats t ON t.timestamp BETWEEN a.startTimestamp AND COALESCE(a.endTimestamp, a.startTimestamp + 60)
        ORDER BY a.startTimestamp DESC
    """)
    fun getCorrelatedThreats(): Flow<List<CorrelatedThreat>>
}

// --- Database (Renamed & Refactored) ---
@Database(entities = [AttackEntity::class, ThreatEntity::class], version = 1, exportSchema = false)
abstract class RaspEvalDatabase : RoomDatabase() {
    abstract fun raspEvalDao(): RaspEvalDao

    companion object {
        @Volatile
        private var INSTANCE: RaspEvalDatabase? = null

        /**
         * Builds the database instance. Called once by RaspEvalBootstrap.
         */
        internal fun build(context: Context): RaspEvalDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    RaspEvalDatabase::class.java,
                    "raspeval_threats.db"
                ).build().also { INSTANCE = it }
            }
        }
    }
}