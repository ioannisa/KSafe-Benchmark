package eu.anifantakis.ksafe_benchmark

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import eu.anifantakis.ksafe_benchmark.ui.theme.KSafeBenchmarkTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            KSafeBenchmarkTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    BenchmarkScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BenchmarkScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var isRunning by remember { mutableStateOf(false) }
    var isInitialized by remember { mutableStateOf(false) }
    var currentStatus by remember { mutableStateOf("Press 'Begin Test' to start") }
    var results by remember { mutableStateOf<List<BenchmarkResult>>(emptyList()) }
    var updateResults by remember { mutableStateOf<List<UpdateResult>>(emptyList()) }
    var reinitResults by remember { mutableStateOf<List<ReinitResult>>(emptyList()) }
    var deletionResults by remember { mutableStateOf<List<DeletionResult>>(emptyList()) }

    val iterationOptions = listOf(1, 50, 100, 200, 500, 1000, 2000)
    var selectedIterations by remember { mutableStateOf(1000) }
    var dropdownExpanded by remember { mutableStateOf(false) }

    val benchmarkRunner = remember { BenchmarkRunner(context) }

    // Initialize on first composition
    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            currentStatus = "Validating encryption keys..."
            benchmarkRunner.validateAndClearInvalidatedKeys()
            currentStatus = "Initializing libraries..."
            benchmarkRunner.initialize()
            isInitialized = true
            currentStatus = "Ready - Press 'Begin Test' to start"
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Header
        Text(
            text = "KSafe Benchmark",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )

        Text(
            text = "vs Competitor Libraries",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Device info
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    text = "Device: ${Build.MODEL}",
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    text = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Dropdown and Start button row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Iterations dropdown
            ExposedDropdownMenuBox(
                expanded = dropdownExpanded,
                onExpandedChange = { if (!isRunning) dropdownExpanded = it },
                modifier = Modifier.width(130.dp)
            ) {
                OutlinedTextField(
                    value = "$selectedIterations",
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Iterations") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = dropdownExpanded) },
                    modifier = Modifier.menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
                    enabled = !isRunning,
                    singleLine = true
                )
                ExposedDropdownMenu(
                    expanded = dropdownExpanded,
                    onDismissRequest = { dropdownExpanded = false }
                ) {
                    iterationOptions.forEach { option ->
                        DropdownMenuItem(
                            text = { Text("$option") },
                            onClick = {
                                selectedIterations = option
                                dropdownExpanded = false
                            }
                        )
                    }
                }
            }

            // Start button
            Button(
                onClick = {
                    scope.launch {
                        isRunning = true
                        results = emptyList()
                        updateResults = emptyList()
                        reinitResults = emptyList()
                        deletionResults = emptyList()
                        benchmarkRunner.baseIterations = selectedIterations

                        withContext(Dispatchers.Default) {
                            // Start overall suite timer
                            benchmarkRunner.startSuiteTimer()

                            // Step 1: Run read/write benchmarks (creates new keys)
                            val benchmarkResults = benchmarkRunner.runAllBenchmarks { status ->
                                currentStatus = status
                            }
                            results = benchmarkResults

                            // Step 2: Run update benchmarks (overwrites existing keys)
                            val updates = benchmarkRunner.runUpdateBenchmarks { status ->
                                currentStatus = status
                            }
                            updateResults = updates

                            // Step 3: Run reinitialization benchmarks (cold start simulation)
                            val reinit = benchmarkRunner.runReinitBenchmarks { status ->
                                currentStatus = status
                            }
                            reinitResults = reinit

                            // Step 4: Run deletion benchmarks (cleanup and measure)
                            val deletion = benchmarkRunner.runDeletionBenchmarks { status ->
                                currentStatus = status
                            }
                            deletionResults = deletion

                            // Print final summary with total time
                            benchmarkRunner.printFinalSummary()
                        }

                        isRunning = false
                    }
                },
                enabled = !isRunning && isInitialized,
                modifier = Modifier.weight(1f)
            ) {
                if (isRunning) {
                    CircularProgressIndicator(
                        modifier = Modifier
                            .height(20.dp)
                            .width(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(if (isRunning) "Running..." else "Begin Test")
            }
        }

        // Status
        Text(
            text = currentStatus,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(vertical = 8.dp)
        )

        // Results
        if (results.isNotEmpty()) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // READ results
                item {
                    Text(
                        text = "READ Performance ($selectedIterations iterations)",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                }

                val readResults = results.filter { it.category == "READ" }
                    .sortedBy { it.avgMicros }
                val maxReadMicros = readResults.maxOfOrNull { it.avgMicros } ?: 1.0

                items(readResults) { result ->
                    BenchmarkResultCard(
                        result = result,
                        maxMicros = maxReadMicros
                    )
                }

                // WRITE results
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "WRITE Performance ($selectedIterations iterations)",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                }

                val writeResults = results.filter { it.category == "WRITE" }
                    .sortedBy { it.avgMicros }
                val maxWriteMicros = writeResults.maxOfOrNull { it.avgMicros } ?: 1.0

                items(writeResults) { result ->
                    BenchmarkResultCard(
                        result = result,
                        maxMicros = maxWriteMicros
                    )
                }

                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    EncryptionOverheadCard(results)
                }

                item {
                    Spacer(modifier = Modifier.height(8.dp))
                    SummaryCard(results)
                }

                // Update results
                if (updateResults.isNotEmpty()) {
                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "UPDATE Performance ($selectedIterations+ keys)",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(vertical = 8.dp)
                        )
                    }

                    item {
                        UpdateResultsCard(updateResults)
                    }
                }

                // Reinitialization results (cold start)
                if (reinitResults.isNotEmpty()) {
                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "COLD START Performance",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(vertical = 8.dp)
                        )
                    }

                    item {
                        ReinitResultsCard(reinitResults)
                    }
                }

                // Deletion results
                if (deletionResults.isNotEmpty()) {
                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "DELETION Performance",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(vertical = 8.dp)
                        )
                    }

                    item {
                        DeletionResultsCard(deletionResults)
                    }
                }

                item {
                    Spacer(modifier = Modifier.height(16.dp))
                }
            }
        }
    }
}

@Composable
fun UpdateResultsCard(updateResults: List<UpdateResult>) {
    // Filter out error results for sorting, but show them separately
    val directResults = updateResults.filter { it.category == "UPDATE" && it.error == null }
    val suspendResults = updateResults.filter { it.category == "UPDATE_SUSPEND" && it.error == null }
    val errorResults = updateResults.filter { it.error != null }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFFF8E1) // Light amber
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Update Performance (Direct API)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFFF8F00)
            )

            Spacer(modifier = Modifier.height(8.dp))

            directResults.sortedBy { it.avgMicros }.forEach { result ->
                val barColor = when {
                    result.isKSafe && result.isEncrypted == true -> Color(0xFF4CAF50)
                    result.isKSafe && result.isEncrypted == false -> Color(0xFF8BC34A)
                    else -> Color(0xFFFF8F00)
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = result.name,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = if (result.isKSafe) FontWeight.Bold else FontWeight.Normal
                    )
                    Text(
                        text = formatMicros(result.avgMicros) + "/op",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold,
                        color = barColor
                    )
                }
            }

            if (suspendResults.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Update Performance (Suspend API)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFF8F00)
                )

                Spacer(modifier = Modifier.height(4.dp))

                suspendResults.sortedBy { it.avgMicros }.forEach { result ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = result.name,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = formatMicros(result.avgMicros) + "/op",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF4CAF50)
                        )
                    }
                }
            }

            // Show error results if any
            if (errorResults.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Failed Benchmarks",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFF5722)
                )

                Spacer(modifier = Modifier.height(4.dp))

                errorResults.forEach { result ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = result.name,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = result.error ?: "Error",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFFF5722)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Measures time to overwrite existing keys with new values.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp
            )
        }
    }
}

@Composable
fun ReinitResultsCard(reinitResults: List<ReinitResult>) {
    val successfulResults = reinitResults.filter { it.totalMs >= 0 }
    val skippedResults = reinitResults.filter { it.totalMs == -2.0 }
    val failedResults = reinitResults.filter { it.totalMs == -1.0 }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFE3F2FD) // Light blue
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Cold Start / Reinitialization",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF1565C0)
            )

            Spacer(modifier = Modifier.height(8.dp))

            successfulResults.sortedBy { it.totalMs }.forEach { result ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            text = result.name,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = if (result.isKSafe) FontWeight.Bold else FontWeight.Normal
                        )
                        Text(
                            text = "${result.keysLoaded} keys loaded",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        text = formatMs(result.totalMs),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF1565C0)
                    )
                }
                if (result != successfulResults.sortedBy { it.totalMs }.last()) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                }
            }

            // Show skipped results (DataStore singleton)
            if (skippedResults.isNotEmpty()) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                skippedResults.forEach { result ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(
                                text = result.name.replace(" (N/A - singleton)", ""),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF757575)
                            )
                            Text(
                                text = "${result.keysLoaded} keys (DataStore singleton)",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFF757575)
                            )
                        }
                        Text(
                            text = "N/A",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF757575)
                        )
                    }
                }
            }

            // Show failed results
            failedResults.forEach { result ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = result.name,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = if (result.isKSafe) FontWeight.Bold else FontWeight.Normal,
                        color = Color(0xFFC62828)
                    )
                    Text(
                        text = "FAILED",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFC62828)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Measures time to load library with existing data (simulates app restart).\nKSafe uses DataStore which requires singleton - reinit not possible in-process.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp
            )
        }
    }
}

@Composable
fun DeletionResultsCard(deletionResults: List<DeletionResult>) {
    val otherResults = deletionResults.filter { it.category == "OTHER" }
    val ksafeEncResults = deletionResults.filter { it.category == "KSAFE_ENC_MEM" }
    val ksafePlainResults = deletionResults.filter { it.category == "KSAFE_PLAIN_MEM" }

    // Other Libraries Card
    if (otherResults.isNotEmpty()) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFFFFEBEE) // Light red
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Other Libraries - Deletion",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFC62828)
                )

                Spacer(modifier = Modifier.height(8.dp))

                otherResults.sortedBy { it.totalMs }.forEach { result ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(
                                text = result.name,
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                text = "${result.keysDeleted} keys",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Text(
                            text = formatMs(result.totalMs),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFC62828)
                        )
                    }
                    if (result != otherResults.sortedBy { it.totalMs }.last()) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
    }

    // KSafe ENCRYPTED mem Card
    if (ksafeEncResults.isNotEmpty()) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFFE8F5E9) // Light green
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "KSafe ENCRYPTED mem - Deletion by Group",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF2E7D32)
                )

                Spacer(modifier = Modifier.height(8.dp))

                ksafeEncResults.forEach { result ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = result.name.removePrefix("KSafe ENC: "),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            text = "${result.keysDeleted} keys  ${formatMs(result.totalMs)}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF2E7D32)
                        )
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "TOTAL",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "${ksafeEncResults.sumOf { it.keysDeleted }} keys  ${formatMs(ksafeEncResults.sumOf { it.totalMs })}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF2E7D32)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
    }

    // KSafe PLAIN_TEXT mem Card
    if (ksafePlainResults.isNotEmpty()) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFFF1F8E9) // Very light green
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "KSafe PLAIN_TEXT mem - Deletion by Group",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF558B2F)
                )

                Spacer(modifier = Modifier.height(8.dp))

                ksafePlainResults.forEach { result ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = result.name.removePrefix("KSafe PLAIN: "),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            text = "${result.keysDeleted} keys  ${formatMs(result.totalMs)}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF558B2F)
                        )
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "TOTAL",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "${ksafePlainResults.sumOf { it.keysDeleted }} keys  ${formatMs(ksafePlainResults.sumOf { it.totalMs })}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF558B2F)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Compares deleteDirect() vs delete() suspend, encrypted vs unencrypted",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 11.sp
                )
            }
        }
    }
}

private fun formatMs(ms: Double): String {
    return when {
        ms < 1 -> String.format("%.2f µs", ms * 1000)
        ms < 1000 -> String.format("%.2f ms", ms)
        else -> String.format("%.2f s", ms / 1000)
    }
}

@Composable
fun BenchmarkResultCard(
    result: BenchmarkResult,
    maxMicros: Double
) {
    // Handle error state
    val hasError = result.error != null

    val barColor = when {
        hasError -> Color(0xFFFF5722) // Orange for errors
        result.isKSafe && result.isEncrypted == true -> Color(0xFF4CAF50) // Green for KSafe encrypted
        result.isKSafe && result.isEncrypted == false -> Color(0xFF8BC34A) // Light green for KSafe unencrypted
        else -> MaterialTheme.colorScheme.primary
    }

    val backgroundColor = when {
        hasError -> Color(0xFFFFEBEE) // Light red for errors
        result.isKSafe && result.isEncrypted == true -> Color(0xFFE8F5E9) // Light green
        result.isKSafe && result.isEncrypted == false -> Color(0xFFF1F8E9) // Very light green
        else -> MaterialTheme.colorScheme.surface
    }

    val barWidth = if (hasError) 0.05f else (result.avgMicros / maxMicros).toFloat().coerceIn(0.05f, 1f)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = backgroundColor)
    ) {
        Column(
            modifier = Modifier.padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.name,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = if (result.isKSafe) FontWeight.Bold else FontWeight.Normal
                    )
                    if (hasError) {
                        Text(
                            text = result.error ?: "Error",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFFF5722),
                            fontSize = 10.sp
                        )
                    } else if (result.isKSafe) {
                        Text(
                            text = if (result.isEncrypted == true) "AES-256-GCM" else "No encryption",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 10.sp
                        )
                    }
                }
                Text(
                    text = if (hasError) "Failed" else formatMicros(result.avgMicros),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                    color = barColor
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            // Progress bar
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(barWidth)
                        .height(8.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(barColor)
                )
            }
        }
    }
}

@Composable
fun EncryptionOverheadCard(results: List<BenchmarkResult>) {
    // Filter out error results for overhead calculations
    val readResults = results.filter { it.category == "READ" && it.isKSafe && it.error == null }
    val writeResults = results.filter { it.category == "WRITE" && it.isKSafe && it.error == null }

    val getDirectEncrypted = readResults.find { it.name.contains("getDirect") && it.isEncrypted == true }
    val getDirectUnencrypted = readResults.find { it.name.contains("getDirect") && it.isEncrypted == false }

    val putDirectEncrypted = writeResults.find { it.name.contains("putDirect") && it.isEncrypted == true }
    val putDirectUnencrypted = writeResults.find { it.name.contains("putDirect") && it.isEncrypted == false }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFFF3E0) // Light orange
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Encryption Overhead",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFE65100)
            )

            Spacer(modifier = Modifier.height(8.dp))

            if (getDirectEncrypted != null && getDirectUnencrypted != null) {
                val readOverhead = ((getDirectEncrypted.avgMicros / getDirectUnencrypted.avgMicros) - 1) * 100
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "getDirect read overhead:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "+${String.format("%.1f", readOverhead)}%",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE65100)
                    )
                }
                Text(
                    text = "${formatMicros(getDirectUnencrypted.avgMicros)} → ${formatMicros(getDirectEncrypted.avgMicros)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(8.dp))

            if (putDirectEncrypted != null && putDirectUnencrypted != null) {
                val writeOverhead = ((putDirectEncrypted.avgMicros / putDirectUnencrypted.avgMicros) - 1) * 100
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "putDirect write overhead:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "+${String.format("%.1f", writeOverhead)}%",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE65100)
                    )
                }
                Text(
                    text = "${formatMicros(putDirectUnencrypted.avgMicros)} → ${formatMicros(putDirectEncrypted.avgMicros)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "The encryption overhead is the cost of AES-256-GCM encryption compared to storing plain values.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 11.sp
            )
        }
    }
}

@Composable
fun SummaryCard(results: List<BenchmarkResult>) {
    val readResults = results.filter { it.category == "READ" }
    val writeResults = results.filter { it.category == "WRITE" }

    val ksafeDirectRead = readResults.find { it.name == "KSafe getDirect (encrypted)" }
    val encryptedPrefsRead = readResults.find { it.name == "EncryptedSharedPrefs" }

    val ksafeDirectWrite = writeResults.find { it.name == "KSafe putDirect (encrypted)" }
    val encryptedPrefsWrite = writeResults.find { it.name == "EncryptedSharedPrefs" }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1E88E5)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Summary vs EncryptedSharedPrefs",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Spacer(modifier = Modifier.height(8.dp))

            if (ksafeDirectRead != null && encryptedPrefsRead != null) {
                val readSpeedup = encryptedPrefsRead.avgMicros / ksafeDirectRead.avgMicros
                Text(
                    text = "KSafe getDirect is ${String.format("%.1f", readSpeedup)}x faster (read)",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color.White
                )
            }

            if (ksafeDirectWrite != null && encryptedPrefsWrite != null) {
                val writeSpeedup = encryptedPrefsWrite.avgMicros / ksafeDirectWrite.avgMicros
                Text(
                    text = "KSafe putDirect is ${String.format("%.1f", writeSpeedup)}x faster (write)",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color.White
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "KSafe getDirect/putDirect use hot cache for instant UI response. " +
                        "KSafe get/put suspend ensure disk persistence.",
                style = MaterialTheme.typography.bodySmall,
                color = Color.White.copy(alpha = 0.8f),
                fontSize = 11.sp
            )
        }
    }
}

private fun formatMicros(micros: Double): String {
    return when {
        micros < 1 -> String.format("%.2f ns", micros * 1000)
        micros < 1000 -> String.format("%.2f µs", micros)
        else -> String.format("%.2f ms", micros / 1000)
    }
}
