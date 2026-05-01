package eu.anifantakis.ksafe_benchmark

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import androidx.datastore.core.DataStore
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.liftric.kvault.KVault
import com.russhwolf.settings.Settings
import com.russhwolf.settings.SharedPreferencesSettings
import com.tencent.mmkv.MMKV
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeMemoryPolicy
import eu.anifantakis.lib.ksafe.KSafeSecurityPolicy
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.SecurityAction
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "benchmark_datastore")

data class BenchmarkResult(
    val name: String,
    val category: String,
    val totalMicros: Double,      // Total time for all iterations
    val avgMicros: Double,        // Average time per operation
    val iterations: Int,
    val isKSafe: Boolean = false,
    val isEncrypted: Boolean? = null, // null for non-KSafe libraries
    val error: String? = null     // Error message if benchmark failed (e.g., concurrency issues in older KSafe)
)

/**
 * Result for library reinitialization benchmark.
 * Measures how long it takes to load a library with existing data.
 */
data class ReinitResult(
    val name: String,
    val keysLoaded: Int,
    val totalMs: Double,          // Total time in milliseconds
    val isKSafe: Boolean = false
)

/**
 * Result for update benchmark.
 * Measures time to overwrite existing keys with new values.
 */
data class UpdateResult(
    val name: String,
    val category: String,         // UPDATE, UPDATE_SUSPEND
    val keysUpdated: Int,
    val totalMicros: Double,
    val avgMicros: Double,
    val isKSafe: Boolean = false,
    val isEncrypted: Boolean? = null,
    val error: String? = null     // Error message if benchmark failed
)

/**
 * Result for deletion/cleanup benchmark.
 * Measures total time to delete all data from a library.
 */
data class DeletionResult(
    val name: String,
    val keysDeleted: Int,
    val totalMs: Double,          // Total time in milliseconds
    val category: String = "OTHER" // KSAFE_DETAIL, OTHER
)

class BenchmarkRunner(private val context: Context) {

    // Configurable base iteration count (can be changed before running benchmarks)
    var baseIterations: Int = 100

    // All benchmarks use the same iteration count for fair comparison
    private val iterations: Int get() = baseIterations
    // No warmup for single iteration (cold test), otherwise 10% of iterations (min 10)
    private val warmupIterations: Int get() = if (baseIterations == 1) 0 else (baseIterations / 10).coerceAtLeast(10)

    // Libraries
    private lateinit var ksafeEncryptedMemory: KSafe  // Default: decrypt on every read (more secure)
    private lateinit var ksafePlainMemory: KSafe      // PLAIN_TEXT: decrypt once, cache plaintext (faster)
    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var plainPrefs: SharedPreferences
    private lateinit var mmkv: MMKV
    private lateinit var multiplatformSettings: Settings
    private lateinit var kvault: KVault               // KVault - encrypted KMP storage

    /**
     * Validates Android Keystore keys used by KSafe and clears any permanently invalidated keys.
     * Keys can become invalidated when the user changes their lock screen or biometric settings.
     * This must be called before initializing KSafe to prevent background crashes.
     */
    fun validateAndClearInvalidatedKeys() {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Find all KSafe-related keys (any key containing "benchmark" which our instances use)
            val ksafeAliases = keyStore.aliases().toList().filter { alias ->
                alias.contains("benchmark", ignoreCase = true) ||
                alias.startsWith("ksafe_", ignoreCase = true)
            }

            Log.d("KSafeBenchmark", "Found ${ksafeAliases.size} potential KSafe keys to validate")

            for (alias in ksafeAliases) {
                validateAndClearKey(keyStore, alias)
            }
        } catch (e: Exception) {
            Log.e("KSafeBenchmark", "Failed to validate KeyStore keys: ${e.message}", e)
        }
    }

    /**
     * Validates a single key and deletes it if permanently invalidated.
     */
    private fun validateAndClearKey(keyStore: KeyStore, alias: String) {
        try {
            val key = keyStore.getKey(alias, null) as? SecretKey
            if (key != null) {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                Log.d("KSafeBenchmark", "Key '$alias' is valid")
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.w("KSafeBenchmark", "Key '$alias' permanently invalidated, deleting...")
            keyStore.deleteEntry(alias)
            Log.i("KSafeBenchmark", "Key '$alias' deleted - will be regenerated")
        } catch (e: Exception) {
            // Check if the actual cause is KeyPermanentlyInvalidatedException
            var cause: Throwable? = e
            while (cause != null) {
                if (cause is KeyPermanentlyInvalidatedException) {
                    Log.w("KSafeBenchmark", "Key '$alias' permanently invalidated (nested), deleting...")
                    keyStore.deleteEntry(alias)
                    Log.i("KSafeBenchmark", "Key '$alias' deleted - will be regenerated")
                    return
                }
                cause = cause.cause
            }
            Log.d("KSafeBenchmark", "Key '$alias' check: ${e.javaClass.simpleName} - ${e.message}")
        }
    }

    fun initialize() {
        val securityPolicy = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.IGNORE,
            debuggerAttached = SecurityAction.IGNORE,
            debugBuild = SecurityAction.IGNORE,
            emulator = SecurityAction.IGNORE
        )

        // KSafe with ENCRYPTED memory policy (default) - decrypt on every read
        ksafeEncryptedMemory = KSafe(
            context = context,
            fileName = "benchmarkencmem",
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            securityPolicy = securityPolicy
        )

        // KSafe with PLAIN_TEXT memory policy - decrypt once, cache plaintext
        ksafePlainMemory = KSafe(
            context = context,
            fileName = "benchmarkplainmem",
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            securityPolicy = securityPolicy
        )

        // Initialize EncryptedSharedPreferences
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        encryptedPrefs = EncryptedSharedPreferences.create(
            context,
            "encrypted_benchmark",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        // Initialize plain SharedPreferences
        plainPrefs = context.getSharedPreferences("plain_benchmark", Context.MODE_PRIVATE)

        // Initialize MMKV
        MMKV.initialize(context)
        mmkv = MMKV.defaultMMKV()

        // Initialize Russell Wolf's multiplatform-settings
        val settingsPrefs = context.getSharedPreferences("multiplatform_settings_benchmark", Context.MODE_PRIVATE)
        multiplatformSettings = SharedPreferencesSettings(settingsPrefs)

        // Initialize KVault (encrypted KMP storage)
        kvault = KVault(context, "kvault_benchmark")

        // No prepopulation - iterations determines key count
        // Benchmark order: WRITE → READ → UPDATE → DELETE
    }

    // Store the total benchmark wall-clock time for reporting
    private var totalBenchmarkTimeMs: Long = 0

    // Track overall suite timing (across all benchmark phases)
    private var suiteStartTimeNanos: Long = 0
    private var suiteEndTimeNanos: Long = 0

    /**
     * Call this before starting any benchmarks to begin the overall timer.
     */
    fun startSuiteTimer() {
        suiteStartTimeNanos = System.nanoTime()
    }

    /**
     * Call this after all benchmarks complete to print the final summary.
     */
    fun printFinalSummary() {
        suiteEndTimeNanos = System.nanoTime()
        val totalSuiteTimeMs = (suiteEndTimeNanos - suiteStartTimeNanos) / 1_000_000
        val totalSuiteTimeSec = totalSuiteTimeMs / 1000.0
        val minutes = (totalSuiteTimeSec / 60).toInt()
        val seconds = totalSuiteTimeSec % 60

        val tag = "KSafeBenchmark"
        Log.d(tag, "")
        Log.d(tag, "╔═════════════════════════════════════════════════════════════╗")
        Log.d(tag, "║           🏁 BENCHMARK SUITE COMPLETE 🏁                    ║")
        Log.d(tag, "╠═════════════════════════════════════════════════════════════╣")
        Log.d(tag, "║ Total time: ${String.format("%d min %.1f sec", minutes, seconds).padEnd(45)}║")
        Log.d(tag, "║ Iterations: ${baseIterations.toString().padEnd(45)}║")
        Log.d(tag, "╚═════════════════════════════════════════════════════════════╝")
    }

    /**
     * Safely run a KSafe benchmark, catching any exceptions (e.g., concurrency issues in older KSafe versions).
     * Returns an error result if the benchmark fails.
     */
    private fun safeKSafeBenchmark(
        name: String,
        category: String,
        isEncrypted: Boolean,
        benchmark: () -> BenchmarkResult
    ): BenchmarkResult {
        return try {
            benchmark()
        } catch (e: Exception) {
            Log.w("KSafeBenchmark", "Benchmark '$name' failed: ${e.message}")
            BenchmarkResult(
                name = name,
                category = category,
                totalMicros = 0.0,
                avgMicros = 0.0,
                iterations = iterations,
                isKSafe = true,
                isEncrypted = isEncrypted,
                error = "Error: ${e.javaClass.simpleName}"
            )
        }
    }

    /**
     * Safely run a KSafe update benchmark, catching any exceptions.
     * Returns an error result if the benchmark fails.
     */
    private fun safeKSafeUpdateBenchmark(
        name: String,
        category: String,
        isEncrypted: Boolean,
        benchmark: () -> UpdateResult
    ): UpdateResult {
        return try {
            benchmark()
        } catch (e: Exception) {
            Log.w("KSafeBenchmark", "Update benchmark '$name' failed: ${e.message}")
            UpdateResult(
                name = name,
                category = category,
                keysUpdated = 0,
                totalMicros = 0.0,
                avgMicros = 0.0,
                isKSafe = true,
                isEncrypted = isEncrypted,
                error = "Error: ${e.javaClass.simpleName}"
            )
        }
    }

    fun runAllBenchmarks(onProgress: (String) -> Unit): List<BenchmarkResult> {
        val overallStartTime = System.nanoTime()
        val results = mutableListOf<BenchmarkResult>()

        // IMPORTANT: WRITE benchmarks run FIRST to create keys
        // Then READ benchmarks read those keys
        // iterations = number of keys created and read

        // ========== UNENCRYPTED WRITE BENCHMARKS ==========
        // Creates keys: key_0 to key_{iterations-1}

        onProgress("Benchmarking SharedPreferences write...")
        results.add(benchmarkPlainPrefsWrite())

        onProgress("Benchmarking MMKV write...")
        results.add(benchmarkMmkvWrite())

        onProgress("Benchmarking Multiplatform Settings write...")
        results.add(benchmarkMultiplatformSettingsWrite())

        onProgress("Benchmarking DataStore write...")
        results.add(benchmarkDataStoreWrite())

        onProgress("Benchmarking KSafe Direct (unencrypted) write...")
        results.add(benchmarkKSafeDirectUnencrypted())

        // ========== ENCRYPTED WRITE BENCHMARKS ==========

        onProgress("Benchmarking EncryptedSharedPreferences write...")
        results.add(benchmarkEncryptedPrefsWrite())

        onProgress("Benchmarking KVault write...")
        results.add(benchmarkKVaultWrite())

        onProgress("Benchmarking KSafe Direct enc (PLAIN_TEXT) write...")
        results.add(safeKSafeBenchmark("KSafe Direct enc (PLAIN_TEXT)", "WRITE", true) {
            benchmarkKSafeDirectEncryptedPlainMem()
        })

        onProgress("Benchmarking KSafe Direct enc (ENCRYPTED) write...")
        results.add(safeKSafeBenchmark("KSafe Direct enc (ENCRYPTED)", "WRITE", true) {
            benchmarkKSafeDirectEncryptedEncMem()
        })

        // ========== SUSPEND API WRITE BENCHMARKS ==========
        // KSafe's coroutine-based API (waits for DataStore completion)

        onProgress("Benchmarking KSafe Coroutine (unencrypted) write...")
        results.add(benchmarkKSafeCoroutineUnencrypted())

        onProgress("Benchmarking KSafe Coroutine enc (PLAIN_TEXT) write...")
        results.add(safeKSafeBenchmark("KSafe Coroutine enc (PLAIN_TEXT)", "WRITE_SUSPEND", true) {
            benchmarkKSafeCoroutineEncryptedPlainMem()
        })

        onProgress("Benchmarking KSafe Coroutine enc (ENCRYPTED) write...")
        results.add(safeKSafeBenchmark("KSafe Coroutine enc (ENCRYPTED)", "WRITE_SUSPEND", true) {
            benchmarkKSafeCoroutineEncryptedEncMem()
        })

        // ========== DELEGATED API WRITE BENCHMARKS ==========
        // KSafe's property delegation API (uses putDirect internally)

        onProgress("Benchmarking KSafe Delegated (unencrypted) write...")
        results.add(benchmarkKSafeDelegatedUnencrypted())

        onProgress("Benchmarking KSafe Delegated enc (PLAIN_TEXT) write...")
        results.add(safeKSafeBenchmark("KSafe Delegated enc (PLAIN_TEXT)", "WRITE_DELEGATED", true) {
            benchmarkKSafeDelegatedEncryptedPlainMem()
        })

        onProgress("Benchmarking KSafe Delegated enc (ENCRYPTED) write...")
        results.add(safeKSafeBenchmark("KSafe Delegated enc (ENCRYPTED)", "WRITE_DELEGATED", true) {
            benchmarkKSafeDelegatedEncryptedEncMem()
        })

        // ========== UNENCRYPTED READ BENCHMARKS ==========
        // Reads keys created above

        onProgress("Benchmarking SharedPreferences read...")
        results.add(benchmarkPlainPrefsRead())

        onProgress("Benchmarking MMKV read...")
        results.add(benchmarkMmkvRead())

        onProgress("Benchmarking Multiplatform Settings read...")
        results.add(benchmarkMultiplatformSettingsRead())

        onProgress("Benchmarking DataStore read...")
        results.add(benchmarkDataStoreRead())

        onProgress("Benchmarking KSafe Direct (unencrypted) read...")
        results.add(benchmarkKSafeDirectUnencryptedRead())

        // ========== ENCRYPTED READ BENCHMARKS ==========

        onProgress("Benchmarking EncryptedSharedPreferences read...")
        results.add(benchmarkEncryptedPrefsRead())

        onProgress("Benchmarking KVault read...")
        results.add(benchmarkKVaultRead())

        onProgress("Benchmarking KSafe Direct enc (PLAIN_TEXT) read...")
        results.add(safeKSafeBenchmark("KSafe Direct enc (PLAIN_TEXT)", "READ", true) {
            benchmarkKSafeDirectEncryptedPlainMemRead()
        })

        onProgress("Benchmarking KSafe Direct enc (ENCRYPTED) read...")
        results.add(safeKSafeBenchmark("KSafe Direct enc (ENCRYPTED)", "READ", true) {
            benchmarkKSafeDirectEncryptedEncMemRead()
        })

        // ========== SUSPEND API READ BENCHMARKS ==========
        // KSafe's coroutine-based API (hits DataStore directly)

        onProgress("Benchmarking KSafe Coroutine (unencrypted) read...")
        results.add(benchmarkKSafeCoroutineUnencryptedRead())

        onProgress("Benchmarking KSafe Coroutine enc (PLAIN_TEXT) read...")
        results.add(safeKSafeBenchmark("KSafe Coroutine enc (PLAIN_TEXT)", "READ_SUSPEND", true) {
            benchmarkKSafeCoroutineEncryptedPlainMemRead()
        })

        onProgress("Benchmarking KSafe Coroutine enc (ENCRYPTED) read...")
        results.add(safeKSafeBenchmark("KSafe Coroutine enc (ENCRYPTED)", "READ_SUSPEND", true) {
            benchmarkKSafeCoroutineEncryptedEncMemRead()
        })

        // ========== DELEGATED API READ BENCHMARKS ==========
        // KSafe's property delegation API (uses getDirect internally)

        onProgress("Benchmarking KSafe Delegated (unencrypted) read...")
        results.add(benchmarkKSafeDelegatedUnencryptedRead())

        onProgress("Benchmarking KSafe Delegated enc (PLAIN_TEXT) read...")
        results.add(safeKSafeBenchmark("KSafe Delegated enc (PLAIN_TEXT)", "READ_DELEGATED", true) {
            benchmarkKSafeDelegatedEncryptedPlainMemRead()
        })

        onProgress("Benchmarking KSafe Delegated enc (ENCRYPTED) read...")
        results.add(safeKSafeBenchmark("KSafe Delegated enc (ENCRYPTED)", "READ_DELEGATED", true) {
            benchmarkKSafeDelegatedEncryptedEncMemRead()
        })

        onProgress("Complete!")

        // Capture total wall-clock time
        val overallEndTime = System.nanoTime()
        totalBenchmarkTimeMs = (overallEndTime - overallStartTime) / 1_000_000

        // Print all results to logcat for easy copy/paste
        printResultsToLogcat(results)

        return results
    }

    private fun printResultsToLogcat(results: List<BenchmarkResult>) {
        val tag = "KSafeBenchmark"

        // Categorize results
        fun isEncryptedLib(name: String) = name.contains("Encrypted") ||
            name.contains("PLAIN_TEXT") || name.contains("ENCRYPTED") ||
            name == "KVault"

        // Include all KSafe API variants (Direct, Coroutine, Delegated) in comparisons
        fun isReadCategory(cat: String) = cat == "READ" || cat == "READ_SUSPEND" || cat == "READ_DELEGATED"
        fun isWriteCategory(cat: String) = cat == "WRITE" || cat == "WRITE_SUSPEND" || cat == "WRITE_DELEGATED"
        fun hasNoError(result: BenchmarkResult) = result.error == null

        // Filter out error results from comparisons
        val unencReadResults = results.filter { isReadCategory(it.category) && !isEncryptedLib(it.name) && hasNoError(it) }
            .sortedBy { it.avgMicros }
        val encReadResults = results.filter { isReadCategory(it.category) && isEncryptedLib(it.name) && hasNoError(it) }
            .sortedBy { it.avgMicros }
        val unencWriteResults = results.filter { isWriteCategory(it.category) && !isEncryptedLib(it.name) && hasNoError(it) }
            .sortedBy { it.avgMicros }
        val encWriteResults = results.filter { isWriteCategory(it.category) && isEncryptedLib(it.name) && hasNoError(it) }
            .sortedBy { it.avgMicros }

        // Collect any error results to report separately
        val errorResults = results.filter { it.error != null }

        Log.d(tag, "")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")
        Log.d(tag, "         KSAFE BENCHMARK RESULTS ($baseIterations iterations)          ")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")

        // ===== UNENCRYPTED READ =====
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│         UNENCRYPTED READ (Fair Comparison)                  │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        unencReadResults.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(35)
            val avg = formatMicros(result.avgMicros).padStart(12)
            Log.d(tag, "│ $rank. $name $avg/op")
        }
        // KSafe vs best competitor
        val bestUnencRead = unencReadResults.firstOrNull { !it.isKSafe }
        val ksafeUnencRead = unencReadResults.find { it.isKSafe }
        if (bestUnencRead != null && ksafeUnencRead != null) {
            val ratio = ksafeUnencRead.avgMicros / bestUnencRead.avgMicros
            Log.d(tag, "│")
            Log.d(tag, "│ KSafe is ${String.format("%.1f", ratio)}x slower than ${bestUnencRead.name}")
            Log.d(tag, "│ (Cost of type-safe generics & cross-platform API)")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== ENCRYPTED READ =====
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│          ENCRYPTED READ (Fair Comparison)                   │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        encReadResults.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(35)
            val avg = formatMicros(result.avgMicros).padStart(12)
            Log.d(tag, "│ $rank. $name $avg/op")
        }
        val espRead = encReadResults.find { it.name == "EncryptedSharedPrefs" }
        val kvaultRead = encReadResults.find { it.name == "KVault" }
        val ksafePlainRead = encReadResults.find { it.name.contains("PLAIN_TEXT mem") }
        val ksafeEncRead = encReadResults.find { it.name.contains("ENCRYPTED mem") }
        Log.d(tag, "│")
        if (espRead != null && ksafePlainRead != null) {
            val speedup = espRead.avgMicros / ksafePlainRead.avgMicros
            Log.d(tag, "│ KSafe PLAIN_TEXT is ${String.format("%.1f", speedup)}x FASTER than ESP!")
        }
        if (kvaultRead != null && ksafePlainRead != null) {
            val speedup = kvaultRead.avgMicros / ksafePlainRead.avgMicros
            Log.d(tag, "│ KSafe PLAIN_TEXT is ${String.format("%.1f", speedup)}x FASTER than KVault!")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== UNENCRYPTED WRITE =====
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│         UNENCRYPTED WRITE (Fair Comparison)                 │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        unencWriteResults.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(35)
            val avg = formatMicros(result.avgMicros).padStart(12)
            Log.d(tag, "│ $rank. $name $avg/op")
        }
        val bestUnencWrite = unencWriteResults.firstOrNull { !it.isKSafe }
        val ksafeUnencWrite = unencWriteResults.find { it.isKSafe }
        if (bestUnencWrite != null && ksafeUnencWrite != null) {
            val ratio = ksafeUnencWrite.avgMicros / bestUnencWrite.avgMicros
            Log.d(tag, "│")
            Log.d(tag, "│ KSafe is ${String.format("%.1f", ratio)}x slower than ${bestUnencWrite.name}")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== ENCRYPTED WRITE =====
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│          ENCRYPTED WRITE (Fair Comparison)                  │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        encWriteResults.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(35)
            val avg = formatMicros(result.avgMicros).padStart(12)
            Log.d(tag, "│ $rank. $name $avg/op")
        }
        val espWrite = encWriteResults.find { it.name == "EncryptedSharedPrefs" }
        val kvaultWrite = encWriteResults.find { it.name == "KVault" }
        val ksafePlainWrite = encWriteResults.find { it.name.contains("PLAIN_TEXT mem") }
        Log.d(tag, "│")
        if (espWrite != null && ksafePlainWrite != null) {
            val ratio = espWrite.avgMicros / ksafePlainWrite.avgMicros
            if (ratio > 1) {
                Log.d(tag, "│ KSafe PLAIN_TEXT is ${String.format("%.1f", ratio)}x FASTER than ESP!")
            } else {
                Log.d(tag, "│ KSafe PLAIN_TEXT is ${String.format("%.1f", 1/ratio)}x slower than ESP")
            }
        }
        if (kvaultWrite != null && ksafePlainWrite != null) {
            val ratio = kvaultWrite.avgMicros / ksafePlainWrite.avgMicros
            if (ratio > 1) {
                Log.d(tag, "│ KSafe PLAIN_TEXT is ${String.format("%.1f", ratio)}x FASTER than KVault!")
            } else {
                Log.d(tag, "│ KSafe PLAIN_TEXT is ${String.format("%.1f", 1/ratio)}x slower than KVault")
            }
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== DATASTORE ACCELERATION (KEY INSIGHT!) =====
        val dataStoreRead = unencReadResults.find { it.name == "DataStore" }
        val dataStoreWrite = unencWriteResults.find { it.name == "DataStore" }

        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│    ⚡ DATASTORE ACCELERATION (KSafe uses DataStore internally) │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        if (dataStoreRead != null && ksafeUnencRead != null) {
            val speedup = dataStoreRead.avgMicros / ksafeUnencRead.avgMicros
            Log.d(tag, "│ READ:  KSafe is ${String.format("%.0f", speedup)}x FASTER than vanilla DataStore!")
            Log.d(tag, "│   DataStore: ${formatMicros(dataStoreRead.avgMicros)}")
            Log.d(tag, "│   KSafe:     ${formatMicros(ksafeUnencRead.avgMicros)}")
        }
        Log.d(tag, "│")
        if (dataStoreWrite != null && ksafeUnencWrite != null) {
            val speedup = dataStoreWrite.avgMicros / ksafeUnencWrite.avgMicros
            Log.d(tag, "│ WRITE: KSafe is ${String.format("%.0f", speedup)}x FASTER than vanilla DataStore!")
            Log.d(tag, "│   DataStore: ${formatMicros(dataStoreWrite.avgMicros)}")
            Log.d(tag, "│   KSafe:     ${formatMicros(ksafeUnencWrite.avgMicros)}")
        }
        Log.d(tag, "│")
        Log.d(tag, "│ KSafe's hot cache architecture provides instant access")
        Log.d(tag, "│ while DataStore persists data asynchronously in background.")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== MEMORY POLICY INSIGHT =====
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│          MEMORY POLICY INSIGHT (ENCRYPTED vs PLAIN_TEXT)    │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        if (ksafeEncRead != null && ksafePlainRead != null) {
            val speedup = ksafeEncRead.avgMicros / ksafePlainRead.avgMicros
            Log.d(tag, "│ READ: PLAIN_TEXT is ${String.format("%.0f", speedup)}x faster!")
            Log.d(tag, "│   ENCRYPTED mem:  ${formatMicros(ksafeEncRead.avgMicros)} (decrypt every read)")
            Log.d(tag, "│   PLAIN_TEXT mem: ${formatMicros(ksafePlainRead.avgMicros)} (decrypt once)")
        }
        Log.d(tag, "│")
        Log.d(tag, "│ Use ENCRYPTED for: tokens, passwords, API keys")
        Log.d(tag, "│ Use PLAIN_TEXT for: settings, themes, UI state")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== DIRECT vs SUSPEND API COMPARISON =====
        val suspendReadResults = results.filter { it.category == "READ_SUSPEND" }
            .sortedBy { it.avgMicros }
        val suspendWriteResults = results.filter { it.category == "WRITE_SUSPEND" }
            .sortedBy { it.avgMicros }

        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│      ⚡ DIRECT API vs SUSPEND API (Hot Cache vs DataStore)   │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│")
        Log.d(tag, "│ READ COMPARISON:                                            │")
        val directReadUnenc = ksafeUnencRead
        val suspendReadUnenc = suspendReadResults.find { !it.isEncrypted!! }
        val suspendReadEnc = suspendReadResults.find { it.isEncrypted!! }
        if (directReadUnenc != null && suspendReadUnenc != null) {
            val speedup = suspendReadUnenc.avgMicros / directReadUnenc.avgMicros
            Log.d(tag, "│   Unencrypted:")
            Log.d(tag, "│     getDirect(): ${formatMicros(directReadUnenc.avgMicros).padStart(12)} (Hot Cache)")
            Log.d(tag, "│     get():       ${formatMicros(suspendReadUnenc.avgMicros).padStart(12)} (DataStore)")
            Log.d(tag, "│     → getDirect() is ${String.format("%.1f", speedup)}x FASTER")
        }
        if (ksafePlainRead != null && suspendReadEnc != null) {
            val speedup = suspendReadEnc.avgMicros / ksafePlainRead.avgMicros
            Log.d(tag, "│   Encrypted:")
            Log.d(tag, "│     getDirect(): ${formatMicros(ksafePlainRead.avgMicros).padStart(12)} (Hot Cache)")
            Log.d(tag, "│     get():       ${formatMicros(suspendReadEnc.avgMicros).padStart(12)} (DataStore)")
            Log.d(tag, "│     → getDirect() is ${String.format("%.1f", speedup)}x FASTER")
        }
        Log.d(tag, "│")
        Log.d(tag, "│ WRITE COMPARISON:                                           │")
        val suspendWriteUnenc = suspendWriteResults.find { !it.isEncrypted!! }
        val suspendWriteEnc = suspendWriteResults.find { it.isEncrypted!! }
        if (ksafeUnencWrite != null && suspendWriteUnenc != null) {
            val speedup = suspendWriteUnenc.avgMicros / ksafeUnencWrite.avgMicros
            Log.d(tag, "│   Unencrypted:")
            Log.d(tag, "│     putDirect(): ${formatMicros(ksafeUnencWrite.avgMicros).padStart(12)} (queue + return)")
            Log.d(tag, "│     put():       ${formatMicros(suspendWriteUnenc.avgMicros).padStart(12)} (wait for disk)")
            Log.d(tag, "│     → putDirect() is ${String.format("%.1f", speedup)}x FASTER")
        }
        val ksafeEncWrite = encWriteResults.find { it.name.contains("PLAIN_TEXT mem") }
        if (ksafeEncWrite != null && suspendWriteEnc != null) {
            val speedup = suspendWriteEnc.avgMicros / ksafeEncWrite.avgMicros
            Log.d(tag, "│   Encrypted:")
            Log.d(tag, "│     putDirect(): ${formatMicros(ksafeEncWrite.avgMicros).padStart(12)} (queue + return)")
            Log.d(tag, "│     put():       ${formatMicros(suspendWriteEnc.avgMicros).padStart(12)} (wait for disk)")
            Log.d(tag, "│     → putDirect() is ${String.format("%.1f", speedup)}x FASTER")
        }
        Log.d(tag, "│")
        Log.d(tag, "│ WHEN TO USE EACH:                                           │")
        Log.d(tag, "│   getDirect/putDirect: UI thread, property delegation       │")
        Log.d(tag, "│   get/put:             Must guarantee data is persisted     │")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== SUMMARY =====
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│                         SUMMARY                             │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│ ⚡ VS DATASTORE (KSafe's backend - THE KEY COMPARISON):     │")
        if (dataStoreRead != null && ksafeUnencRead != null) {
            val speedup = dataStoreRead.avgMicros / ksafeUnencRead.avgMicros
            Log.d(tag, "│   READ:  ${String.format("%.0f", speedup)}x FASTER than vanilla DataStore")
        }
        if (dataStoreWrite != null && ksafeUnencWrite != null) {
            val speedup = dataStoreWrite.avgMicros / ksafeUnencWrite.avgMicros
            Log.d(tag, "│   WRITE: ${String.format("%.0f", speedup)}x FASTER than vanilla DataStore")
        }
        Log.d(tag, "│")
        Log.d(tag, "│ VS Other Libraries:                                         │")
        if (bestUnencRead != null && ksafeUnencRead != null && bestUnencRead.name != "DataStore") {
            val ratio = ksafeUnencRead.avgMicros / bestUnencRead.avgMicros
            Log.d(tag, "│   Unenc READ:  ${String.format("%.1f", ratio)}x slower than ${bestUnencRead.name}")
        }
        if (bestUnencWrite != null && ksafeUnencWrite != null && bestUnencWrite.name != "DataStore") {
            val ratio = ksafeUnencWrite.avgMicros / bestUnencWrite.avgMicros
            Log.d(tag, "│   Unenc WRITE: ${String.format("%.1f", ratio)}x slower than ${bestUnencWrite.name}")
        }
        if (espRead != null && ksafePlainRead != null) {
            val speedup = espRead.avgMicros / ksafePlainRead.avgMicros
            Log.d(tag, "│   Enc READ:  ${String.format("%.1f", speedup)}x FASTER than EncryptedSharedPrefs")
        }
        if (kvaultRead != null && ksafePlainRead != null) {
            val speedup = kvaultRead.avgMicros / ksafePlainRead.avgMicros
            Log.d(tag, "│   Enc READ:  ${String.format("%.1f", speedup)}x FASTER than KVault")
        }
        if (espWrite != null && ksafePlainWrite != null) {
            val ratio = espWrite.avgMicros / ksafePlainWrite.avgMicros
            if (ratio > 1) {
                Log.d(tag, "│   Enc WRITE: ${String.format("%.1f", ratio)}x FASTER than EncryptedSharedPrefs")
            } else {
                Log.d(tag, "│   Enc WRITE: ${String.format("%.1f", 1/ratio)}x slower than EncryptedSharedPrefs")
            }
        }
        if (kvaultWrite != null && ksafePlainWrite != null) {
            val ratio = kvaultWrite.avgMicros / ksafePlainWrite.avgMicros
            if (ratio > 1) {
                Log.d(tag, "│   Enc WRITE: ${String.format("%.1f", ratio)}x FASTER than KVault")
            } else {
                Log.d(tag, "│   Enc WRITE: ${String.format("%.1f", 1/ratio)}x slower than KVault")
            }
        }
        Log.d(tag, "│")
        Log.d(tag, "│ Direct vs Suspend API:                                      │")
        if (directReadUnenc != null && suspendReadUnenc != null) {
            val readSpeedup = suspendReadUnenc.avgMicros / directReadUnenc.avgMicros
            Log.d(tag, "│   getDirect() is ${String.format("%.0f", readSpeedup)}x faster than get() for reads")
        }
        if (ksafeUnencWrite != null && suspendWriteUnenc != null) {
            val writeSpeedup = suspendWriteUnenc.avgMicros / ksafeUnencWrite.avgMicros
            Log.d(tag, "│   putDirect() is ${String.format("%.0f", writeSpeedup)}x faster than put() for writes")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // ===== TIMING ANALYSIS =====
        // Calculate sum of all measured benchmark times
        val sumOfMeasuredMicros = results.sumOf { it.totalMicros }
        val sumOfMeasuredMs = sumOfMeasuredMicros / 1000.0
        val sumOfMeasuredSec = sumOfMeasuredMs / 1000.0
        val totalWallClockSec = totalBenchmarkTimeMs / 1000.0
        val overheadMs = totalBenchmarkTimeMs - sumOfMeasuredMs
        val overheadPercent = if (totalBenchmarkTimeMs > 0) (overheadMs / totalBenchmarkTimeMs) * 100 else 0.0

        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│               ⏱️ TIMING ANALYSIS                             │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│ Total wall-clock time:      ${String.format("%8.2f", totalWallClockSec)} seconds")
        Log.d(tag, "│ Sum of measured benchmarks: ${String.format("%8.2f", sumOfMeasuredSec)} seconds")
        Log.d(tag, "│ Overhead (warmup, logging): ${String.format("%8.2f", overheadMs / 1000.0)} seconds (${String.format("%.1f", overheadPercent)}%)")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│ Breakdown by library (measured time only):                  │")

        // Group by library and sum total time
        data class LibraryTiming(val name: String, val totalMs: Double, val isKSafe: Boolean)
        val libraryTimings = results.groupBy {
            // Extract base library name (remove " (Direct)", " (Coroutine)", etc.)
            when {
                it.name.contains("KSafe") -> "KSafe (all variants)"
                else -> it.name
            }
        }.map { (name, benchmarks) ->
            LibraryTiming(name, benchmarks.sumOf { it.totalMicros } / 1000.0, benchmarks.any { it.isKSafe })
        }.sortedByDescending { it.totalMs }

        libraryTimings.forEach { lib ->
            val marker = if (lib.isKSafe) "⚡" else "  "
            Log.d(tag, "│ $marker ${lib.name.padEnd(32)} ${String.format("%8.2f", lib.totalMs)} ms")
        }

        // Highlight KSafe's total time
        val ksafeTotalMs = libraryTimings.find { it.isKSafe }?.totalMs ?: 0.0
        val otherLibsTotalMs = libraryTimings.filter { !it.isKSafe }.sumOf { it.totalMs }
        Log.d(tag, "│")
        Log.d(tag, "│ KSafe total:       ${String.format("%8.2f", ksafeTotalMs)} ms")
        Log.d(tag, "│ Other libs total:  ${String.format("%8.2f", otherLibsTotalMs)} ms")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // Report any failed benchmarks (e.g., concurrency issues in older KSafe versions)
        if (errorResults.isNotEmpty()) {
            Log.d(tag, "")
            Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
            Log.d(tag, "│               ⚠️ FAILED BENCHMARKS                           │")
            Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
            errorResults.forEach { result ->
                val name = result.name.padEnd(35)
                Log.d(tag, "│ $name ${result.error}")
            }
            Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
            Log.d(tag, "│ Note: Older KSafe versions (< 1.4.1) have concurrency       │")
            Log.d(tag, "│ issues with encrypted operations. Upgrade to 1.4.1+.        │")
            Log.d(tag, "└─────────────────────────────────────────────────────────────┘")
        }

        Log.d(tag, "")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")
    }

    private fun formatMicros(micros: Double): String {
        // Always format in ms for consistency
        val ms = micros / 1000.0
        return when {
            ms < 1 -> String.format("%.4f ms", ms)
            ms < 1000 -> String.format("%.2f ms", ms)
            else -> String.format("%.2f s", ms / 1000)
        }
    }

    // Always format in ms for direct comparison
    private fun formatMicrosRaw(micros: Double): String {
        val ms = micros / 1000.0
        return when {
            ms < 1 -> String.format("%.4f ms", ms)
            ms < 1000 -> String.format("%.2f ms", ms)
            else -> String.format("%.2f s", ms / 1000)
        }
    }

    // ========== READ BENCHMARKS ==========
    // Each API reads keys with unique prefixes created by its corresponding write benchmark
    //
    // KSafe 9 categories (3 API types × 3 encryption modes):
    //   Direct API:    ksafe_direct_unencrypted_key_, ksafe_direct_encrypted_PLAIN_TEXT_key_, ksafe_direct_encrypted_ENCRYPTED_key_
    //   Coroutine API: ksafe_coroutine_unencrypted_key_, ksafe_coroutine_encrypted_PLAIN_TEXT_key_, ksafe_coroutine_encrypted_ENCRYPTED_key_
    //   Delegated API: (to be added) ksafe_delegated_unencrypted_key_, etc.

    // ========== KSafe DIRECT API READ ==========

    // Direct API - Unencrypted read
    private fun benchmarkKSafeDirectUnencryptedRead(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.getDirect("ksafe_direct_unencrypted_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            ksafePlainMemory.getDirect("ksafe_direct_unencrypted_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Direct (unencrypted)",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Direct API - Encrypted read with PLAIN_TEXT memory policy
    private fun benchmarkKSafeDirectEncryptedPlainMemRead(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.getDirect("ksafe_direct_encrypted_PLAIN_TEXT_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            ksafePlainMemory.getDirect("ksafe_direct_encrypted_PLAIN_TEXT_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Direct enc (PLAIN_TEXT)",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Direct API - Encrypted read with ENCRYPTED memory policy (decrypts every read)
    private fun benchmarkKSafeDirectEncryptedEncMemRead(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafeEncryptedMemory.getDirect("ksafe_direct_encrypted_ENCRYPTED_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            ksafeEncryptedMemory.getDirect("ksafe_direct_encrypted_ENCRYPTED_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Direct enc (ENCRYPTED)",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // ========== KSafe COROUTINE/SUSPEND API READ ==========

    // Coroutine API - Unencrypted read
    //
    // Fires every iteration as a `GlobalScope.launch` so they all dispatch
    // immediately on `Dispatchers.Default` (no event-loop interleaving on a
    // single thread). Then `runBlocking { joinAll() }` waits for every job
    // before measuring elapsed time. This represents real-app concurrency
    // (multiple coroutines reading at once) rather than artificial one-at-
    // a-time awaits.
    @OptIn(DelicateCoroutinesApi::class)
    private fun benchmarkKSafeCoroutineUnencryptedRead(): BenchmarkResult {
        runBlocking {
            repeat(warmupIterations) {
                ksafePlainMemory.get("ksafe_coroutine_unencrypted_key_0", "")
            }
        }

        val start = System.nanoTime()
        val jobs = (0 until iterations).map { i ->
            GlobalScope.launch {
                ksafePlainMemory.get("ksafe_coroutine_unencrypted_key_$i", "")
            }
        }
        runBlocking { jobs.joinAll() }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Coroutine (unencrypted)",
            category = "READ_SUSPEND",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Coroutine API - Encrypted read with PLAIN_TEXT memory policy
    @OptIn(DelicateCoroutinesApi::class)
    private fun benchmarkKSafeCoroutineEncryptedPlainMemRead(): BenchmarkResult {
        runBlocking {
            repeat(warmupIterations) {
                ksafePlainMemory.get("ksafe_coroutine_encrypted_PLAIN_TEXT_key_0", "")
            }
        }

        val start = System.nanoTime()
        val jobs = (0 until iterations).map { i ->
            GlobalScope.launch {
                ksafePlainMemory.get("ksafe_coroutine_encrypted_PLAIN_TEXT_key_$i", "")
            }
        }
        runBlocking { jobs.joinAll() }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Coroutine enc (PLAIN_TEXT)",
            category = "READ_SUSPEND",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Coroutine API - Encrypted read with ENCRYPTED memory policy
    @OptIn(DelicateCoroutinesApi::class)
    private fun benchmarkKSafeCoroutineEncryptedEncMemRead(): BenchmarkResult {
        runBlocking {
            repeat(warmupIterations) {
                ksafeEncryptedMemory.get("ksafe_coroutine_encrypted_ENCRYPTED_key_0", "")
            }
        }

        val start = System.nanoTime()
        val jobs = (0 until iterations).map { i ->
            GlobalScope.launch {
                ksafeEncryptedMemory.get("ksafe_coroutine_encrypted_ENCRYPTED_key_$i", "")
            }
        }
        runBlocking { jobs.joinAll() }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Coroutine enc (ENCRYPTED)",
            category = "READ_SUSPEND",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // ========== KSafe DELEGATED API READ ==========
    // Reads keys written by Delegated API write benchmarks
    // Note: Delegated API uses getDirect() internally, so read benchmarks use getDirect()

    // Delegated API - Unencrypted read
    private fun benchmarkKSafeDelegatedUnencryptedRead(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.getDirect("ksafe_delegated_unencrypted_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            ksafePlainMemory.getDirect("ksafe_delegated_unencrypted_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Delegated (unencrypted)",
            category = "READ_DELEGATED",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Delegated API - Encrypted read with PLAIN_TEXT memory policy
    private fun benchmarkKSafeDelegatedEncryptedPlainMemRead(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.getDirect("ksafe_delegated_encrypted_PLAIN_TEXT_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            ksafePlainMemory.getDirect("ksafe_delegated_encrypted_PLAIN_TEXT_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Delegated enc (PLAIN_TEXT)",
            category = "READ_DELEGATED",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Delegated API - Encrypted read with ENCRYPTED memory policy
    private fun benchmarkKSafeDelegatedEncryptedEncMemRead(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafeEncryptedMemory.getDirect("ksafe_delegated_encrypted_ENCRYPTED_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            ksafeEncryptedMemory.getDirect("ksafe_delegated_encrypted_ENCRYPTED_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Delegated enc (ENCRYPTED)",
            category = "READ_DELEGATED",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    private fun benchmarkEncryptedPrefsRead(): BenchmarkResult {
        repeat(warmupIterations) {
            encryptedPrefs.getString("esp_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            encryptedPrefs.getString("esp_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "EncryptedSharedPrefs",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkPlainPrefsRead(): BenchmarkResult {
        repeat(warmupIterations) {
            plainPrefs.getString("sp_key_0", "")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            plainPrefs.getString("sp_key_$it", "")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "SharedPreferences",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkMmkvRead(): BenchmarkResult {
        repeat(warmupIterations) {
            mmkv.decodeString("mmkv_key_0")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            mmkv.decodeString("mmkv_key_$it")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "MMKV",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkDataStoreRead(): BenchmarkResult {
        repeat(warmupIterations) {
            runBlocking {
                context.dataStore.data.first()[stringPreferencesKey("ds_key_0")]
            }
        }

        val start = System.nanoTime()
        repeat(iterations) {
            runBlocking {
                context.dataStore.data.first()[stringPreferencesKey("ds_key_$it")]
            }
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "DataStore",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkMultiplatformSettingsRead(): BenchmarkResult {
        repeat(warmupIterations) {
            multiplatformSettings.getStringOrNull("mps_key_0")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            multiplatformSettings.getStringOrNull("mps_key_$it")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "Multiplatform Settings",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    // ========== WRITE BENCHMARKS ==========
    // Each API uses unique key prefixes to ensure fresh writes (not updates)
    //
    // KSafe 9 categories (3 API types × 3 encryption modes):
    //   Direct API:    ksafe_direct_unencrypted_key_, ksafe_direct_encrypted_PLAIN_TEXT_key_, ksafe_direct_encrypted_ENCRYPTED_key_
    //   Coroutine API: ksafe_coroutine_unencrypted_key_, ksafe_coroutine_encrypted_PLAIN_TEXT_key_, ksafe_coroutine_encrypted_ENCRYPTED_key_
    //   Delegated API: (to be added) ksafe_delegated_unencrypted_key_, etc.
    //
    // Other libraries: sp_key_, mmkv_key_, mps_key_, ds_key_, esp_key_, kv_key_

    // ========== KSafe DIRECT API WRITE ==========

    // Direct API - Unencrypted (PLAIN_TEXT memory)
    private fun benchmarkKSafeDirectUnencrypted(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.putDirect("_warmup", "warmup", KSafeWriteMode.Plain)
        }
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_direct_unencrypted_key_$i", "value_$i", KSafeWriteMode.Plain)
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Direct (unencrypted)",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Direct API - Encrypted with PLAIN_TEXT memory policy
    private fun benchmarkKSafeDirectEncryptedPlainMem(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.putDirect("_warmup", "warmup", KSafeWriteMode.Encrypted())
        }
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_direct_encrypted_PLAIN_TEXT_key_$i", "value_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Direct enc (PLAIN_TEXT)",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Direct API - Encrypted with ENCRYPTED memory policy
    private fun benchmarkKSafeDirectEncryptedEncMem(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafeEncryptedMemory.putDirect("_warmup", "warmup", KSafeWriteMode.Encrypted())
        }
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafeEncryptedMemory.putDirect("ksafe_direct_encrypted_ENCRYPTED_key_$i", "value_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Direct enc (ENCRYPTED)",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // ========== KSafe COROUTINE/SUSPEND API WRITE ==========

    // Coroutine API - Unencrypted
    // Fires every iteration as a `GlobalScope.launch` (dispatched immediately on
    // Dispatchers.Default) and waits for completion via `joinAll`. This represents
    // real-app concurrency where multiple coroutines call put() in parallel and
    // the write coalescer batches them.
    @OptIn(DelicateCoroutinesApi::class)
    private fun benchmarkKSafeCoroutineUnencrypted(): BenchmarkResult {
        runBlocking {
            repeat(warmupIterations) {
                ksafePlainMemory.put("_warmup", "warmup", KSafeWriteMode.Plain)
            }
        }

        val start = System.nanoTime()
        val jobs = (0 until iterations).map { i ->
            GlobalScope.launch {
                ksafePlainMemory.put("ksafe_coroutine_unencrypted_key_$i", "value_$i", KSafeWriteMode.Plain)
            }
        }
        runBlocking { jobs.joinAll() }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Coroutine (unencrypted)",
            category = "WRITE_SUSPEND",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Coroutine API - Encrypted with PLAIN_TEXT memory policy
    @OptIn(DelicateCoroutinesApi::class)
    private fun benchmarkKSafeCoroutineEncryptedPlainMem(): BenchmarkResult {
        runBlocking {
            repeat(warmupIterations) {
                ksafePlainMemory.put("_warmup", "warmup", KSafeWriteMode.Encrypted())
            }
        }

        val start = System.nanoTime()
        val jobs = (0 until iterations).map { i ->
            GlobalScope.launch {
                ksafePlainMemory.put("ksafe_coroutine_encrypted_PLAIN_TEXT_key_$i", "value_$i", KSafeWriteMode.Encrypted())
            }
        }
        runBlocking { jobs.joinAll() }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Coroutine enc (PLAIN_TEXT)",
            category = "WRITE_SUSPEND",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Coroutine API - Encrypted with ENCRYPTED memory policy
    @OptIn(DelicateCoroutinesApi::class)
    private fun benchmarkKSafeCoroutineEncryptedEncMem(): BenchmarkResult {
        runBlocking {
            repeat(warmupIterations) {
                ksafeEncryptedMemory.put("_warmup", "warmup", KSafeWriteMode.Encrypted())
            }
        }

        val start = System.nanoTime()
        val jobs = (0 until iterations).map { i ->
            GlobalScope.launch {
                ksafeEncryptedMemory.put("ksafe_coroutine_encrypted_ENCRYPTED_key_$i", "value_$i", KSafeWriteMode.Encrypted())
            }
        }
        runBlocking { jobs.joinAll() }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Coroutine enc (ENCRYPTED)",
            category = "WRITE_SUSPEND",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // ========== KSafe DELEGATED API WRITE ==========
    // Uses property delegation: by ksafe()

    // Delegated API - Unencrypted (PLAIN_TEXT memory)
    private fun benchmarkKSafeDelegatedUnencrypted(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.putDirect("_warmup", "warmup", KSafeWriteMode.Plain)
        }
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_delegated_unencrypted_key_$i", "value_$i", KSafeWriteMode.Plain)
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Delegated (unencrypted)",
            category = "WRITE_DELEGATED",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Delegated API - Encrypted with PLAIN_TEXT memory policy
    private fun benchmarkKSafeDelegatedEncryptedPlainMem(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafePlainMemory.putDirect("_warmup", "warmup", KSafeWriteMode.Encrypted())
        }
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_delegated_encrypted_PLAIN_TEXT_key_$i", "value_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Delegated enc (PLAIN_TEXT)",
            category = "WRITE_DELEGATED",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Delegated API - Encrypted with ENCRYPTED memory policy
    private fun benchmarkKSafeDelegatedEncryptedEncMem(): BenchmarkResult {
        repeat(warmupIterations) {
            ksafeEncryptedMemory.putDirect("_warmup", "warmup", KSafeWriteMode.Encrypted())
        }
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafeEncryptedMemory.putDirect("ksafe_delegated_encrypted_ENCRYPTED_key_$i", "value_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KSafe Delegated enc (ENCRYPTED)",
            category = "WRITE_DELEGATED",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    private fun benchmarkEncryptedPrefsWrite(): BenchmarkResult {
        repeat(warmupIterations) {
            encryptedPrefs.edit().putString("_warmup", "warmup").apply()
        }

        val start = System.nanoTime()
        repeat(iterations) { i ->
            encryptedPrefs.edit().putString("esp_key_$i", "value_$i").apply()
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "EncryptedSharedPrefs",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkPlainPrefsWrite(): BenchmarkResult {
        repeat(warmupIterations) {
            plainPrefs.edit().putString("_warmup", "warmup").apply()
        }

        val start = System.nanoTime()
        repeat(iterations) {
            plainPrefs.edit().putString("sp_key_$it", "value_$it").apply()
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "SharedPreferences",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkMmkvWrite(): BenchmarkResult {
        repeat(warmupIterations) {
            mmkv.encode("_warmup", "warmup")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            mmkv.encode("mmkv_key_$it", "value_$it")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "MMKV",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkDataStoreWrite(): BenchmarkResult {
        repeat(warmupIterations) {
            runBlocking {
                context.dataStore.edit { prefs ->
                    prefs[stringPreferencesKey("_warmup")] = "warmup"
                }
            }
        }

        val start = System.nanoTime()
        repeat(iterations) {
            runBlocking {
                context.dataStore.edit { prefs ->
                    prefs[stringPreferencesKey("ds_key_$it")] = "value_$it"
                }
            }
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "DataStore",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkMultiplatformSettingsWrite(): BenchmarkResult {
        repeat(warmupIterations) {
            multiplatformSettings.putString("_warmup", "warmup")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            multiplatformSettings.putString("mps_key_$it", "value_$it")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "Multiplatform Settings",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    // ========== KVAULT BENCHMARKS ==========
    // KVault uses Android Keystore for encryption (similar to EncryptedSharedPreferences)
    // Key prefix: kv_key_

    private fun benchmarkKVaultRead(): BenchmarkResult {
        repeat(warmupIterations) {
            kvault.string("kv_key_0")
        }

        val start = System.nanoTime()
        repeat(iterations) {
            kvault.string("kv_key_$it")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KVault",
            category = "READ",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    private fun benchmarkKVaultWrite(): BenchmarkResult {
        repeat(warmupIterations) {
            kvault.set("_warmup", "warmup")
        }

        val start = System.nanoTime()
        repeat(iterations) { i ->
            kvault.set("kv_key_$i", "value_$i")
        }
        val elapsed = System.nanoTime() - start

        return BenchmarkResult(
            name = "KVault",
            category = "WRITE",
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            iterations = iterations
        )
    }

    // ========== UPDATE BENCHMARKS ==========

    /**
     * Runs update benchmarks - overwrites ALL existing keys with new values.
     * This measures update performance vs initial write performance.
     */
    fun runUpdateBenchmarks(onProgress: (String) -> Unit): List<UpdateResult> {
        val results = mutableListOf<UpdateResult>()
        val tag = "KSafeBenchmark"

        Log.d(tag, "")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")
        Log.d(tag, "                    UPDATE BENCHMARK                           ")
        Log.d(tag, "         (Overwriting existing keys with new values)           ")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")

        // ========== KSafe Direct API updates ==========
        onProgress("Updating KSafe Direct (unencrypted)...")
        results.add(updateKSafeDirectUnencrypted())

        onProgress("Updating KSafe Direct enc (PLAIN_TEXT)...")
        results.add(safeKSafeUpdateBenchmark("KSafe Direct enc (PLAIN_TEXT)", "UPDATE", true) {
            updateKSafeDirectEncryptedPlainMem()
        })

        onProgress("Updating KSafe Direct enc (ENCRYPTED)...")
        results.add(safeKSafeUpdateBenchmark("KSafe Direct enc (ENCRYPTED)", "UPDATE", true) {
            updateKSafeDirectEncryptedEncMem()
        })

        // ========== KSafe Coroutine/Suspend API updates ==========
        onProgress("Updating KSafe Coroutine (unencrypted)...")
        results.add(updateKSafeCoroutineUnencrypted())

        onProgress("Updating KSafe Coroutine enc (PLAIN_TEXT)...")
        results.add(safeKSafeUpdateBenchmark("KSafe Coroutine enc (PLAIN_TEXT)", "UPDATE_SUSPEND", true) {
            updateKSafeCoroutineEncryptedPlainMem()
        })

        onProgress("Updating KSafe Coroutine enc (ENCRYPTED)...")
        results.add(safeKSafeUpdateBenchmark("KSafe Coroutine enc (ENCRYPTED)", "UPDATE_SUSPEND", true) {
            updateKSafeCoroutineEncryptedEncMem()
        })

        // ========== KSafe Delegated API updates ==========
        onProgress("Updating KSafe Delegated (unencrypted)...")
        results.add(updateKSafeDelegatedUnencrypted())

        onProgress("Updating KSafe Delegated enc (PLAIN_TEXT)...")
        results.add(safeKSafeUpdateBenchmark("KSafe Delegated enc (PLAIN_TEXT)", "UPDATE_DELEGATED", true) {
            updateKSafeDelegatedEncryptedPlainMem()
        })

        onProgress("Updating KSafe Delegated enc (ENCRYPTED)...")
        results.add(safeKSafeUpdateBenchmark("KSafe Delegated enc (ENCRYPTED)", "UPDATE_DELEGATED", true) {
            updateKSafeDelegatedEncryptedEncMem()
        })

        // ========== Other libraries ==========
        onProgress("Updating EncryptedSharedPreferences...")
        results.add(updateEncryptedPrefs())

        onProgress("Updating SharedPreferences...")
        results.add(updatePlainPrefs())

        onProgress("Updating MMKV...")
        results.add(updateMmkv())

        onProgress("Updating DataStore...")
        results.add(updateDataStore())

        onProgress("Updating Multiplatform Settings...")
        results.add(updateMultiplatformSettings())

        onProgress("Updating KVault...")
        results.add(updateKVault())

        // Print update results
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│                    UPDATE RESULTS                           │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")

        val directResults = results.filter { it.category == "UPDATE" }
        directResults.sortedBy { it.avgMicros }.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(35)
            val avg = formatMicros(result.avgMicros).padStart(12)
            Log.d(tag, "│ $rank. $name $avg/op")
        }

        val suspendResults = results.filter { it.category == "UPDATE_SUSPEND" }
        if (suspendResults.isNotEmpty()) {
            Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
            Log.d(tag, "│                 UPDATE (Suspend API)                        │")
            Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
            suspendResults.sortedBy { it.avgMicros }.forEachIndexed { index, result ->
                val rank = index + 1
                val name = result.name.padEnd(35)
                val avg = formatMicros(result.avgMicros).padStart(12)
                Log.d(tag, "│ $rank. $name $avg/op")
            }
        }

        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        return results
    }

    // ========== KSafe UPDATE BENCHMARKS ==========
    // Updates keys written by the write benchmarks using new 9-category naming

    // ========== KSafe DIRECT API UPDATE ==========

    // Direct API - Update unencrypted keys
    // Updates keys: ksafe_direct_unencrypted_key_0 to ksafe_direct_unencrypted_key_{iterations-1}
    private fun updateKSafeDirectUnencrypted(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_direct_unencrypted_key_$i", "updated_$i", KSafeWriteMode.Plain)
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Direct (unencrypted)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Direct API - Update encrypted keys with PLAIN_TEXT memory policy
    // Updates keys: ksafe_direct_encrypted_PLAIN_TEXT_key_0 to ksafe_direct_encrypted_PLAIN_TEXT_key_{iterations-1}
    private fun updateKSafeDirectEncryptedPlainMem(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_direct_encrypted_PLAIN_TEXT_key_$i", "updated_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Direct enc (PLAIN_TEXT)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Direct API - Update encrypted keys with ENCRYPTED memory policy
    // Updates keys: ksafe_direct_encrypted_ENCRYPTED_key_0 to ksafe_direct_encrypted_ENCRYPTED_key_{iterations-1}
    private fun updateKSafeDirectEncryptedEncMem(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafeEncryptedMemory.putDirect("ksafe_direct_encrypted_ENCRYPTED_key_$i", "updated_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Direct enc (ENCRYPTED)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // ========== KSafe COROUTINE/SUSPEND API UPDATE ==========

    // Coroutine API - Update unencrypted keys
    // Updates keys: ksafe_coroutine_unencrypted_key_0 to ksafe_coroutine_unencrypted_key_{iterations-1}
    private fun updateKSafeCoroutineUnencrypted(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_coroutine_unencrypted_key_$i", "updated_$i", KSafeWriteMode.Plain)
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Coroutine (unencrypted)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Coroutine API - Update encrypted keys with PLAIN_TEXT memory policy
    // Updates keys: ksafe_coroutine_encrypted_PLAIN_TEXT_key_0 to ksafe_coroutine_encrypted_PLAIN_TEXT_key_{iterations-1}
    private fun updateKSafeCoroutineEncryptedPlainMem(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_coroutine_encrypted_PLAIN_TEXT_key_$i", "updated_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Coroutine enc (PLAIN_TEXT)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Coroutine API - Update encrypted keys with ENCRYPTED memory policy
    // Updates keys: ksafe_coroutine_encrypted_ENCRYPTED_key_0 to ksafe_coroutine_encrypted_ENCRYPTED_key_{iterations-1}
    private fun updateKSafeCoroutineEncryptedEncMem(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafeEncryptedMemory.putDirect("ksafe_coroutine_encrypted_ENCRYPTED_key_$i", "updated_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Coroutine enc (ENCRYPTED)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // ========== KSafe DELEGATED API UPDATE ==========

    // Delegated API - Update unencrypted keys
    // Updates keys: ksafe_delegated_unencrypted_key_0 to ksafe_delegated_unencrypted_key_{iterations-1}
    private fun updateKSafeDelegatedUnencrypted(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_delegated_unencrypted_key_$i", "updated_$i", KSafeWriteMode.Plain)
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Delegated (unencrypted)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = false
        )
    }

    // Delegated API - Update encrypted keys with PLAIN_TEXT memory policy
    // Updates keys: ksafe_delegated_encrypted_PLAIN_TEXT_key_0 to ksafe_delegated_encrypted_PLAIN_TEXT_key_{iterations-1}
    private fun updateKSafeDelegatedEncryptedPlainMem(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafePlainMemory.putDirect("ksafe_delegated_encrypted_PLAIN_TEXT_key_$i", "updated_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Delegated enc (PLAIN_TEXT)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // Delegated API - Update encrypted keys with ENCRYPTED memory policy
    // Updates keys: ksafe_delegated_encrypted_ENCRYPTED_key_0 to ksafe_delegated_encrypted_ENCRYPTED_key_{iterations-1}
    private fun updateKSafeDelegatedEncryptedEncMem(): UpdateResult {
        val start = System.nanoTime()
        repeat(iterations) { i ->
            ksafeEncryptedMemory.putDirect("ksafe_delegated_encrypted_ENCRYPTED_key_$i", "updated_$i", KSafeWriteMode.Encrypted())
        }
        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KSafe Delegated enc (ENCRYPTED)",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations,
            isKSafe = true,
            isEncrypted = true
        )
    }

    // EncryptedSharedPreferences update
    // Updates keys: esp_key_0 to esp_key_{iterations-1}
    private fun updateEncryptedPrefs(): UpdateResult {
        val start = System.nanoTime()

        repeat(iterations) { i ->
            encryptedPrefs.edit().putString("esp_key_$i", "updated_$i").apply()
        }

        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "EncryptedSharedPrefs",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations
        )
    }

    // SharedPreferences update
    // Updates keys: sp_key_0 to sp_key_{iterations-1}
    private fun updatePlainPrefs(): UpdateResult {
        val start = System.nanoTime()

        repeat(iterations) { i ->
            plainPrefs.edit().putString("sp_key_$i", "updated_$i").apply()
        }

        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "SharedPreferences",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations
        )
    }

    // MMKV update
    // Updates keys: mmkv_key_0 to mmkv_key_{iterations-1}
    private fun updateMmkv(): UpdateResult {
        val start = System.nanoTime()

        repeat(iterations) { i ->
            mmkv.encode("mmkv_key_$i", "updated_$i")
        }

        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "MMKV",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations
        )
    }

    // DataStore update
    // Updates keys: ds_key_0 to ds_key_{iterations-1}
    private fun updateDataStore(): UpdateResult {
        val start = System.nanoTime()

        runBlocking {
            repeat(iterations) { i ->
                context.dataStore.edit { prefs ->
                    prefs[stringPreferencesKey("ds_key_$i")] = "updated_$i"
                }
            }
        }

        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "DataStore",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations
        )
    }

    // Multiplatform Settings update
    // Updates keys: mps_key_0 to mps_key_{iterations-1}
    private fun updateMultiplatformSettings(): UpdateResult {
        val start = System.nanoTime()

        repeat(iterations) { i ->
            multiplatformSettings.putString("mps_key_$i", "updated_$i")
        }

        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "Multiplatform Settings",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations
        )
    }

    // KVault update
    // Updates keys: kv_key_0 to kv_key_{iterations-1}
    private fun updateKVault(): UpdateResult {
        val start = System.nanoTime()

        repeat(iterations) { i ->
            kvault.set("kv_key_$i", "updated_$i")
        }

        val elapsed = System.nanoTime() - start

        return UpdateResult(
            name = "KVault",
            category = "UPDATE",
            keysUpdated = iterations,
            totalMicros = elapsed / 1000.0,
            avgMicros = elapsed / 1000.0 / iterations
        )
    }

    // ========== REINITIALIZATION BENCHMARKS ==========

    /**
     * Reinitializes all libraries and measures load time with existing data.
     * This simulates app cold start with persisted data.
     */
    fun runReinitBenchmarks(onProgress: (String) -> Unit): List<ReinitResult> {
        val results = mutableListOf<ReinitResult>()
        val tag = "KSafeBenchmark"

        Log.d(tag, "")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")
        Log.d(tag, "              REINITIALIZATION BENCHMARK (Cold Start)          ")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")

        // KSafe cache re-population benchmark
        // Since DataStore is singleton, we can't truly reinitialize. Instead, we clear
        // the in-memory cache and measure how long it takes to re-populate from DataStore.
        Log.d(tag, "│ NOTE: KSafe measures cache re-population time (DataStore is singleton)")
        Log.d(tag, "│ Clears memoryCache, then triggers reload via getDirect()")

        // KSafe ENCRYPTED memory policy
        onProgress("Re-populating KSafe ENCRYPTED cache...")
        try {
            results.add(reinitKSafeCacheEncrypted())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit KSafe ENCRYPTED cache: ${e.message}", e)
            results.add(ReinitResult("KSafe ENCRYPTED (FAILED)", 0, -1.0, isKSafe = true))
        }

        // KSafe PLAIN_TEXT memory policy
        onProgress("Re-populating KSafe PLAIN_TEXT cache...")
        try {
            results.add(reinitKSafeCachePlainText())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit KSafe PLAIN_TEXT cache: ${e.message}", e)
            results.add(ReinitResult("KSafe PLAIN_TEXT (FAILED)", 0, -1.0, isKSafe = true))
        }

        // EncryptedSharedPreferences
        onProgress("Reinitializing EncryptedSharedPreferences...")
        try {
            results.add(reinitEncryptedPrefs())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit EncryptedSharedPrefs: ${e.message}", e)
            results.add(ReinitResult("EncryptedSharedPrefs (FAILED)", 0, -1.0))
        }

        // Plain SharedPreferences
        onProgress("Reinitializing SharedPreferences...")
        try {
            results.add(reinitPlainPrefs())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit SharedPreferences: ${e.message}", e)
            results.add(ReinitResult("SharedPreferences (FAILED)", 0, -1.0))
        }

        // MMKV
        onProgress("Reinitializing MMKV...")
        try {
            results.add(reinitMmkv())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit MMKV: ${e.message}", e)
            results.add(ReinitResult("MMKV (FAILED)", 0, -1.0))
        }

        // DataStore
        onProgress("Reinitializing DataStore...")
        try {
            results.add(reinitDataStore())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit DataStore: ${e.message}", e)
            results.add(ReinitResult("DataStore (FAILED)", 0, -1.0))
        }

        // Multiplatform Settings
        onProgress("Reinitializing Multiplatform Settings...")
        try {
            results.add(reinitMultiplatformSettings())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit Multiplatform Settings: ${e.message}", e)
            results.add(ReinitResult("Multiplatform Settings (FAILED)", 0, -1.0))
        }

        // KVault
        onProgress("Reinitializing KVault...")
        try {
            results.add(reinitKVault())
        } catch (e: Exception) {
            Log.e(tag, "Failed to reinit KVault: ${e.message}", e)
            results.add(ReinitResult("KVault (FAILED)", 0, -1.0))
        }

        // Print results (filter out failed/skipped ones for sorting, show them at end)
        val successfulResults = results.filter { it.totalMs >= 0 }
        val skippedResults = results.filter { it.totalMs == -2.0 }
        val failedResults = results.filter { it.totalMs == -1.0 }

        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│          REINITIALIZATION RESULTS (Cold Start)              │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        successfulResults.sortedBy { it.totalMs }.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(30)
            val keys = "${result.keysLoaded} keys".padStart(10)
            val time = formatMs(result.totalMs).padStart(12)
            Log.d(tag, "│ $rank. $name $keys $time")
        }
        failedResults.forEach { result ->
            Log.d(tag, "│ X. ${result.name.padEnd(30)} FAILED")
        }

        // KSafe comparison (only if both succeeded)
        val plainText = results.find { it.name.contains("PLAIN_TEXT") && it.totalMs > 0 }
        val encrypted = results.find { it.name.contains("ENCRYPTED") && !it.name.contains("EncryptedShared") && it.totalMs > 0 }
        if (plainText != null && encrypted != null && plainText.totalMs > encrypted.totalMs) {
            Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
            Log.d(tag, "│ KSafe ENCRYPTED is ${String.format("%.1f", plainText.totalMs / encrypted.totalMs)}x faster to load")
            Log.d(tag, "│ (PLAIN_TEXT decrypts all values on load, ENCRYPTED defers)")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        return results
    }

    private fun reinitKSafePlainText(): ReinitResult {
        // Count existing keys before reinit
        val keyCount = estimateKSafePlainMemKeyCount()

        // Force garbage collection to simulate cold start
        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        // Create new instance - this triggers data loading
        val newInstance = KSafe(
            context = context,
            fileName = "benchmarkplainmem",
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            securityPolicy = KSafeSecurityPolicy(
                rootedDevice = SecurityAction.IGNORE,
                debuggerAttached = SecurityAction.IGNORE,
                debugBuild = SecurityAction.IGNORE,
                emulator = SecurityAction.IGNORE
            )
        )
        // Force cache to be populated by reading a value
        newInstance.getDirect("key_0", "")
        val elapsed = System.nanoTime() - start

        // Update our reference
        ksafePlainMemory = newInstance

        return ReinitResult(
            name = "KSafe PLAIN_TEXT mem",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0,
            isKSafe = true
        )
    }

    private fun reinitKSafeEncrypted(): ReinitResult {
        val keyCount = estimateKSafeEncMemKeyCount()

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        val newInstance = KSafe(
            context = context,
            fileName = "benchmarkencmem",
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            securityPolicy = KSafeSecurityPolicy(
                rootedDevice = SecurityAction.IGNORE,
                debuggerAttached = SecurityAction.IGNORE,
                debugBuild = SecurityAction.IGNORE,
                emulator = SecurityAction.IGNORE
            )
        )
        // Force cache to be populated
        newInstance.getDirect("key_0", "")
        val elapsed = System.nanoTime() - start

        ksafeEncryptedMemory = newInstance

        return ReinitResult(
            name = "KSafe ENCRYPTED mem",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0,
            isKSafe = true
        )
    }

    /**
     * Clears KSafe's internal cache using reflection and measures re-population time.
     * This simulates what happens when the app restarts and needs to reload data from DataStore.
     */
    private fun reinitKSafeCacheEncrypted(): ReinitResult {
        val keyCount = estimateKSafeEncMemKeyCount()

        // Clear the internal cache using reflection
        clearKSafeCache(ksafeEncryptedMemory)

        // Force garbage collection
        System.gc()
        Thread.sleep(100)

        // Measure time to re-populate cache via getDirect
        val start = System.nanoTime()
        ksafeEncryptedMemory.getDirect("ksafe_direct_encrypted_ENCRYPTED_key_0", "")
        val elapsed = System.nanoTime() - start

        return ReinitResult(
            name = "KSafe ENCRYPTED",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0,
            isKSafe = true
        )
    }

    /**
     * Clears KSafe's internal cache using reflection and measures re-population time.
     */
    private fun reinitKSafeCachePlainText(): ReinitResult {
        val keyCount = estimateKSafePlainMemKeyCount()

        // Clear the internal cache using reflection
        clearKSafeCache(ksafePlainMemory)

        // Force garbage collection
        System.gc()
        Thread.sleep(100)

        // Measure time to re-populate cache via getDirect
        val start = System.nanoTime()
        ksafePlainMemory.getDirect("ksafe_direct_unencrypted_key_0", "")
        val elapsed = System.nanoTime() - start

        return ReinitResult(
            name = "KSafe PLAIN_TEXT",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0,
            isKSafe = true
        )
    }

    /**
     * Clears KSafe's internal memoryCache and resets cacheInitialized flag using reflection.
     * This allows us to measure cache re-population time without recreating the DataStore.
     *
     * Layout differs by KSafe version:
     *  - 1.4.0:    KSafe.memoryCache = AtomicReference<Map>
     *  - 1.4.1+:   KSafe.memoryCache = ConcurrentHashMap, KSafe.cacheInitialized = AtomicBoolean
     *  - 2.0.0+:   KSafe.core = KSafeCore; KSafeCore.memoryCache = KSafeConcurrentMap (clear()),
     *              KSafeCore.cacheInitialized = KSafeAtomicFlag (set(Boolean))
     */
    private fun clearKSafeCache(ksafe: KSafe) {
        try {
            // KSafe 2.0.0+ moved cache state into an internal `core: KSafeCore` delegate.
            // Try that path first, fall back to the legacy in-class fields for 1.4.x.
            val coreField = runCatching { ksafe::class.java.getDeclaredField("core") }.getOrNull()

            val cacheHost: Any
            val cacheHostClass: Class<*>
            if (coreField != null) {
                coreField.isAccessible = true
                val core = coreField.get(ksafe)
                    ?: throw IllegalStateException("KSafe.core was null")
                cacheHost = core
                cacheHostClass = core.javaClass
            } else {
                cacheHost = ksafe
                cacheHostClass = ksafe::class.java
            }

            val memoryCacheField = cacheHostClass.getDeclaredField("memoryCache")
            memoryCacheField.isAccessible = true
            val memoryCacheValue = memoryCacheField.get(cacheHost)

            when {
                // KSafe 2.0.0+: KSafeConcurrentMap wrapper exposes a public clear()
                memoryCacheValue != null &&
                    memoryCacheValue.javaClass.name == "eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap" -> {
                    memoryCacheValue.javaClass.getMethod("clear").invoke(memoryCacheValue)
                }
                memoryCacheValue is java.util.concurrent.ConcurrentHashMap<*, *> -> {
                    // KSafe 1.4.1+ used ConcurrentHashMap directly
                    memoryCacheValue.clear()
                }
                memoryCacheValue is java.util.concurrent.atomic.AtomicReference<*> -> {
                    // KSafe 1.4.0 used AtomicReference<Map>
                    @Suppress("UNCHECKED_CAST")
                    val atomicRef = memoryCacheValue as java.util.concurrent.atomic.AtomicReference<Map<String, Any?>>
                    atomicRef.set(emptyMap())
                }
                else -> {
                    Log.w("KSafeBenchmark", "Unknown memoryCache type: ${memoryCacheValue?.javaClass?.name}")
                }
            }

            // Best-effort: also clear the auxiliary caches that exist in KSafe 2.0.0+
            // so re-population time isn't underestimated.
            for (auxField in arrayOf("plaintextCache", "protectionMap", "dirtyKeys")) {
                try {
                    val f = cacheHostClass.getDeclaredField(auxField).apply { isAccessible = true }
                    val value = f.get(cacheHost) ?: continue
                    runCatching { value.javaClass.getMethod("clear").invoke(value) }
                } catch (_: NoSuchFieldException) {
                    // Field not present in this KSafe version; ignore.
                }
            }

            // Reset cacheInitialized.
            //  - KSafe 1.4.1+:  AtomicBoolean
            //  - KSafe 2.0.0+:  KSafeAtomicFlag (public set(Boolean))
            try {
                val cacheInitializedField = cacheHostClass.getDeclaredField("cacheInitialized")
                cacheInitializedField.isAccessible = true
                when (val flag = cacheInitializedField.get(cacheHost)) {
                    is java.util.concurrent.atomic.AtomicBoolean -> flag.set(false)
                    null -> Log.w("KSafeBenchmark", "cacheInitialized was null")
                    else -> flag.javaClass.getMethod("set", Boolean::class.javaPrimitiveType)
                        .invoke(flag, false)
                }
            } catch (e: NoSuchFieldException) {
                // KSafe 1.4.0 had no cacheInitialized — cache is still cleared, that's fine.
                Log.d("KSafeBenchmark", "cacheInitialized field not found (KSafe 1.4.0) - proceeding without it")
            }
        } catch (e: Exception) {
            Log.e("KSafeBenchmark", "Failed to clear KSafe cache: ${e.message}", e)
            throw e
        }
    }

    /**
     * Estimates key count for KSafe ENCRYPTED memory instance.
     * Keys written (Direct API + Coroutine API + Delegated API with ENCRYPTED memory):
     * - ksafe_direct_encrypted_ENCRYPTED_key_ × iterations
     * - ksafe_coroutine_encrypted_ENCRYPTED_key_ × iterations
     * - ksafe_delegated_encrypted_ENCRYPTED_key_ × iterations
     * - Plus warmup keys
     */
    private fun estimateKSafeEncMemKeyCount(): Int {
        return (iterations * 3) + 3 // 3 categories × iterations + warmup keys
    }

    /**
     * Estimates key count for KSafe PLAIN_TEXT memory instance.
     * Keys written (Direct API + Coroutine API + Delegated API with PLAIN_TEXT memory):
     * - ksafe_direct_unencrypted_key_ × iterations
     * - ksafe_direct_encrypted_PLAIN_TEXT_key_ × iterations
     * - ksafe_coroutine_unencrypted_key_ × iterations
     * - ksafe_coroutine_encrypted_PLAIN_TEXT_key_ × iterations
     * - ksafe_delegated_unencrypted_key_ × iterations
     * - ksafe_delegated_encrypted_PLAIN_TEXT_key_ × iterations
     * - Plus warmup keys
     */
    private fun estimateKSafePlainMemKeyCount(): Int {
        return (iterations * 6) + 6 // 6 categories × iterations + warmup keys
    }

    private fun reinitEncryptedPrefs(): ReinitResult {
        val keyCount = encryptedPrefs.all.size

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        val newPrefs = EncryptedSharedPreferences.create(
            context,
            "encrypted_benchmark",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        // Force load by reading
        newPrefs.getString("key_0", "")
        val elapsed = System.nanoTime() - start

        encryptedPrefs = newPrefs

        return ReinitResult(
            name = "EncryptedSharedPrefs",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun reinitPlainPrefs(): ReinitResult {
        val keyCount = plainPrefs.all.size

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        val newPrefs = context.getSharedPreferences("plain_benchmark", Context.MODE_PRIVATE)
        // Force load
        newPrefs.getString("key_0", "")
        val elapsed = System.nanoTime() - start

        plainPrefs = newPrefs

        return ReinitResult(
            name = "SharedPreferences",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun reinitMmkv(): ReinitResult {
        val keyCount = mmkv.allKeys()?.size ?: 0

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        val newMmkv = MMKV.defaultMMKV()
        // Force load
        newMmkv.decodeString("key_0")
        val elapsed = System.nanoTime() - start

        mmkv = newMmkv

        return ReinitResult(
            name = "MMKV",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun reinitDataStore(): ReinitResult {
        var keyCount = 0
        runBlocking {
            keyCount = context.dataStore.data.first().asMap().size
        }

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        // DataStore is a singleton via delegate, so we just force a fresh read
        runBlocking {
            context.dataStore.data.first()
        }
        val elapsed = System.nanoTime() - start

        return ReinitResult(
            name = "DataStore",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun reinitMultiplatformSettings(): ReinitResult {
        val keyCount = multiplatformSettings.keys.size

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        val settingsPrefs = context.getSharedPreferences("multiplatform_settings_benchmark", Context.MODE_PRIVATE)
        val newSettings = SharedPreferencesSettings(settingsPrefs)
        // Force load
        newSettings.getStringOrNull("key_0")
        val elapsed = System.nanoTime() - start

        multiplatformSettings = newSettings

        return ReinitResult(
            name = "Multiplatform Settings",
            keysLoaded = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun reinitKVault(): ReinitResult {
        // KVault doesn't expose key count
        val estimatedKeys = 100 + warmupIterations + iterations

        System.gc()
        Thread.sleep(100)

        val start = System.nanoTime()
        val newKvault = KVault(context, "kvault_benchmark")
        // Force load
        newKvault.string("key_0")
        val elapsed = System.nanoTime() - start

        kvault = newKvault

        return ReinitResult(
            name = "KVault",
            keysLoaded = estimatedKeys,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun formatMs(ms: Double): String {
        // Always format in ms for consistency
        return when {
            ms < 1 -> String.format("%.4f ms", ms)
            ms < 1000 -> String.format("%.2f ms", ms)
            else -> String.format("%.2f s", ms / 1000)
        }
    }

    // ========== DELETION BENCHMARKS ==========

    /**
     * Deletes all test data from all libraries and returns timing results.
     * Shows TOTAL deletion time per library (not average per key).
     * KSafe deletion is broken down by key group to show performance differences.
     */
    fun runDeletionBenchmarks(onProgress: (String) -> Unit): List<DeletionResult> {
        val results = mutableListOf<DeletionResult>()
        val tag = "KSafeBenchmark"

        Log.d(tag, "")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")
        Log.d(tag, "                    DELETION BENCHMARK                         ")
        Log.d(tag, "═══════════════════════════════════════════════════════════════")

        // ========== KSafe Direct API - delete keys ==========
        onProgress("Deleting KSafe Direct API keys...")

        // Direct API - unencrypted keys (from PLAIN_TEXT memory instance)
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafePlainMemory,
            name = "KSafe Direct: unencrypted",
            keyPrefix = "ksafe_direct_unencrypted_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_DIRECT"
        ))

        // Direct API - encrypted keys with PLAIN_TEXT memory policy
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafePlainMemory,
            name = "KSafe Direct: enc PLAIN_TEXT",
            keyPrefix = "ksafe_direct_encrypted_PLAIN_TEXT_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_DIRECT"
        ))

        // Direct API - encrypted keys with ENCRYPTED memory policy
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafeEncryptedMemory,
            name = "KSafe Direct: enc ENCRYPTED",
            keyPrefix = "ksafe_direct_encrypted_ENCRYPTED_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_DIRECT"
        ))

        // ========== KSafe Coroutine/Suspend API - delete keys ==========
        onProgress("Deleting KSafe Coroutine API keys...")

        // Coroutine API - unencrypted keys
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafePlainMemory,
            name = "KSafe Coroutine: unencrypted",
            keyPrefix = "ksafe_coroutine_unencrypted_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_COROUTINE"
        ))

        // Coroutine API - encrypted keys with PLAIN_TEXT memory policy
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafePlainMemory,
            name = "KSafe Coroutine: enc PLAIN_TEXT",
            keyPrefix = "ksafe_coroutine_encrypted_PLAIN_TEXT_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_COROUTINE"
        ))

        // Coroutine API - encrypted keys with ENCRYPTED memory policy
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafeEncryptedMemory,
            name = "KSafe Coroutine: enc ENCRYPTED",
            keyPrefix = "ksafe_coroutine_encrypted_ENCRYPTED_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_COROUTINE"
        ))

        // ========== KSafe Delegated API - delete keys ==========
        onProgress("Deleting KSafe Delegated API keys...")

        // Delegated API - unencrypted keys
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafePlainMemory,
            name = "KSafe Delegated: unencrypted",
            keyPrefix = "ksafe_delegated_unencrypted_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_DELEGATED"
        ))

        // Delegated API - encrypted keys with PLAIN_TEXT memory policy
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafePlainMemory,
            name = "KSafe Delegated: enc PLAIN_TEXT",
            keyPrefix = "ksafe_delegated_encrypted_PLAIN_TEXT_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_DELEGATED"
        ))

        // Delegated API - encrypted keys with ENCRYPTED memory policy
        results.add(deleteKSafeKeyGroup(
            ksafe = ksafeEncryptedMemory,
            name = "KSafe Delegated: enc ENCRYPTED",
            keyPrefix = "ksafe_delegated_encrypted_ENCRYPTED_key_",
            count = iterations,
            useSuspend = false,
            category = "KSAFE_DELEGATED"
        ))

        // ========== Other Libraries ==========
        onProgress("Deleting EncryptedSharedPreferences...")
        results.add(deleteSharedPrefs(encryptedPrefs, "EncryptedSharedPrefs"))

        onProgress("Deleting SharedPreferences...")
        results.add(deleteSharedPrefs(plainPrefs, "SharedPreferences"))

        onProgress("Deleting MMKV...")
        results.add(deleteMmkv())

        onProgress("Deleting DataStore...")
        results.add(deleteDataStore())

        onProgress("Deleting Multiplatform Settings...")
        results.add(deleteMultiplatformSettings())

        onProgress("Deleting KVault...")
        results.add(deleteKVault())

        // Print deletion results - Other Libraries
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│              DELETION RESULTS - Other Libraries             │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        results.filter { it.category == "OTHER" }.sortedBy { it.totalMs }.forEachIndexed { index, result ->
            val rank = index + 1
            val name = result.name.padEnd(25)
            val keys = "${result.keysDeleted} keys".padStart(10)
            val time = formatMs(result.totalMs).padStart(12)
            Log.d(tag, "│ $rank. $name $keys $time")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // Print KSafe Direct API deletion details
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│           DELETION RESULTS - KSafe Direct API               │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        results.filter { it.category == "KSAFE_DIRECT" }.forEach { result ->
            val name = result.name.removePrefix("KSafe Direct: ").padEnd(25)
            val keys = "${result.keysDeleted} keys".padStart(10)
            val time = formatMs(result.totalMs).padStart(12)
            Log.d(tag, "│   $name $keys $time")
        }
        val directTotal = results.filter { it.category == "KSAFE_DIRECT" }.sumOf { it.totalMs }
        val directKeys = results.filter { it.category == "KSAFE_DIRECT" }.sumOf { it.keysDeleted }
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│   TOTAL                     ${("$directKeys keys").padStart(10)} ${formatMs(directTotal).padStart(12)}")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // Print KSafe Coroutine API deletion details
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│          DELETION RESULTS - KSafe Coroutine API             │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        results.filter { it.category == "KSAFE_COROUTINE" }.forEach { result ->
            val name = result.name.removePrefix("KSafe Coroutine: ").padEnd(25)
            val keys = "${result.keysDeleted} keys".padStart(10)
            val time = formatMs(result.totalMs).padStart(12)
            Log.d(tag, "│   $name $keys $time")
        }
        val coroutineTotal = results.filter { it.category == "KSAFE_COROUTINE" }.sumOf { it.totalMs }
        val coroutineKeys = results.filter { it.category == "KSAFE_COROUTINE" }.sumOf { it.keysDeleted }
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│   TOTAL                     ${("$coroutineKeys keys").padStart(10)} ${formatMs(coroutineTotal).padStart(12)}")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // Print KSafe Delegated API deletion details
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│          DELETION RESULTS - KSafe Delegated API             │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        results.filter { it.category == "KSAFE_DELEGATED" }.forEach { result ->
            val name = result.name.removePrefix("KSafe Delegated: ").padEnd(25)
            val keys = "${result.keysDeleted} keys".padStart(10)
            val time = formatMs(result.totalMs).padStart(12)
            Log.d(tag, "│   $name $keys $time")
        }
        val delegatedTotal = results.filter { it.category == "KSAFE_DELEGATED" }.sumOf { it.totalMs }
        val delegatedKeys = results.filter { it.category == "KSAFE_DELEGATED" }.sumOf { it.keysDeleted }
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        Log.d(tag, "│   TOTAL                     ${("$delegatedKeys keys").padStart(10)} ${formatMs(delegatedTotal).padStart(12)}")
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")

        // Wait for async deletions to flush to disk
        onProgress("Flushing deletions to disk...")
        Thread.sleep(500)

        // Verify all libraries are empty
        onProgress("Verifying cleanup...")
        verifyCleanup(tag)

        onProgress("Deletion complete!")
        return results
    }

    /**
     * Verifies that all libraries are empty after deletion.
     * Logs warnings if any data remains.
     */
    private fun verifyCleanup(tag: String) {
        Log.d(tag, "")
        Log.d(tag, "┌─────────────────────────────────────────────────────────────┐")
        Log.d(tag, "│              CLEANUP VERIFICATION                           │")
        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")

        var allEmpty = true

        // EncryptedSharedPreferences
        val espCount = encryptedPrefs.all.size
        if (espCount > 0) {
            Log.w(tag, "│ ⚠️  EncryptedSharedPrefs: $espCount keys remaining!")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  EncryptedSharedPrefs: empty")
        }

        // Plain SharedPreferences
        val spCount = plainPrefs.all.size
        if (spCount > 0) {
            Log.w(tag, "│ ⚠️  SharedPreferences: $spCount keys remaining!")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  SharedPreferences: empty")
        }

        // MMKV
        val mmkvCount = mmkv.allKeys()?.size ?: 0
        if (mmkvCount > 0) {
            Log.w(tag, "│ ⚠️  MMKV: $mmkvCount keys remaining!")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  MMKV: empty")
        }

        // DataStore
        var dsCount = 0
        runBlocking {
            dsCount = context.dataStore.data.first().asMap().size
        }
        if (dsCount > 0) {
            Log.w(tag, "│ ⚠️  DataStore: $dsCount keys remaining!")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  DataStore: empty")
        }

        // Multiplatform Settings
        val msCount = multiplatformSettings.keys.size
        if (msCount > 0) {
            Log.w(tag, "│ ⚠️  Multiplatform Settings: $msCount keys remaining!")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  Multiplatform Settings: empty")
        }

        // KVault - no way to count keys, so we try to read a known key
        val kvaultTestKey = kvault.string("key_0")
        if (kvaultTestKey != null) {
            Log.w(tag, "│ ⚠️  KVault: may have remaining keys (key_0 exists)")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  KVault: appears empty")
        }

        // KSafe - try to read known keys to verify deletion
        val ksafeEncTest = ksafeEncryptedMemory.getDirect("key_0", "")
        val ksafePlainTest = ksafePlainMemory.getDirect("key_0", "")
        if (ksafeEncTest.isNotEmpty() || ksafePlainTest.isNotEmpty()) {
            Log.w(tag, "│ ⚠️  KSafe: may have remaining keys")
            allEmpty = false
        } else {
            Log.d(tag, "│ ✓  KSafe ENCRYPTED mem: appears empty")
            Log.d(tag, "│ ✓  KSafe PLAIN_TEXT mem: appears empty")
        }

        Log.d(tag, "├─────────────────────────────────────────────────────────────┤")
        if (allEmpty) {
            Log.d(tag, "│ ✓  ALL LIBRARIES VERIFIED EMPTY - Ready for next benchmark")
        } else {
            Log.w(tag, "│ ⚠️  SOME LIBRARIES HAVE REMAINING DATA")
        }
        Log.d(tag, "└─────────────────────────────────────────────────────────────┘")
    }

    /**
     * Deletes a specific group of keys from KSafe and measures the time.
     */
    private fun deleteKSafeKeyGroup(
        ksafe: KSafe,
        name: String,
        keyPrefix: String,
        count: Int,
        useSuspend: Boolean,
        category: String
    ): DeletionResult {
        val start = System.nanoTime()

        if (useSuspend) {
            runBlocking {
                repeat(count) { i ->
                    ksafe.delete("$keyPrefix$i")
                }
            }
        } else {
            repeat(count) { i ->
                ksafe.deleteDirect("$keyPrefix$i")
            }
        }

        val elapsed = System.nanoTime() - start

        return DeletionResult(
            name = name,
            keysDeleted = count,
            totalMs = elapsed / 1_000_000.0,
            category = category
        )
    }

    private fun deleteSharedPrefs(prefs: SharedPreferences, name: String): DeletionResult {
        val keyCount = prefs.all.size

        val start = System.nanoTime()
        prefs.edit().clear().apply()
        val elapsed = System.nanoTime() - start

        return DeletionResult(
            name = name,
            keysDeleted = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun deleteMmkv(): DeletionResult {
        val keyCount = mmkv.allKeys()?.size ?: 0

        val start = System.nanoTime()
        mmkv.clearAll()
        val elapsed = System.nanoTime() - start

        return DeletionResult(
            name = "MMKV",
            keysDeleted = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun deleteDataStore(): DeletionResult {
        var keyCount = 0

        val start = System.nanoTime()
        runBlocking {
            val prefs = context.dataStore.data.first()
            keyCount = prefs.asMap().size
            context.dataStore.edit { it.clear() }
        }
        val elapsed = System.nanoTime() - start

        return DeletionResult(
            name = "DataStore",
            keysDeleted = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun deleteMultiplatformSettings(): DeletionResult {
        val keyCount = multiplatformSettings.keys.size

        val start = System.nanoTime()
        multiplatformSettings.clear()
        val elapsed = System.nanoTime() - start

        return DeletionResult(
            name = "Multiplatform Settings",
            keysDeleted = keyCount,
            totalMs = elapsed / 1_000_000.0
        )
    }

    private fun deleteKVault(): DeletionResult {
        // Keys created: kv_key_0 to kv_key_{iterations-1} + _warmup
        val estimatedKeys = iterations + 1

        val start = System.nanoTime()
        kvault.clear()
        val elapsed = System.nanoTime() - start

        return DeletionResult(
            name = "KVault",
            keysDeleted = estimatedKeys,
            totalMs = elapsed / 1_000_000.0
        )
    }
}
