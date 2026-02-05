package dev.fzer0x.imsicatcherdetector2

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Place
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import dev.fzer0x.imsicatcherdetector2.data.ForensicEvent
import dev.fzer0x.imsicatcherdetector2.service.ForensicService
import dev.fzer0x.imsicatcherdetector2.ui.theme.IMSICatcherDetector2Theme
import dev.fzer0x.imsicatcherdetector2.ui.viewmodel.ForensicViewModel
import org.osmdroid.config.Configuration
import org.osmdroid.tileprovider.tilesource.TileSourceFactory
import org.osmdroid.util.GeoPoint
import org.osmdroid.views.MapView
import org.osmdroid.views.overlay.Marker
import org.osmdroid.views.overlay.Polygon
import org.osmdroid.views.overlay.Polyline
import org.osmdroid.views.overlay.mylocation.GpsMyLocationProvider
import org.osmdroid.views.overlay.mylocation.MyLocationNewOverlay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
    private val viewModel: ForensicViewModel by viewModels()

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        if (permissions.all { it.value }) { startForensicService() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Configuration.getInstance().userAgentValue = packageName
        checkAndRequestPermissions()
        setContent {
            IMSICatcherDetector2Theme {
                MainContainer(viewModel)
            }
        }
    }

    private fun checkAndRequestPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.INTERNET
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (permissions.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }) {
            startForensicService()
        } else {
            requestPermissionLauncher.launch(permissions.toTypedArray())
        }
    }

    private fun startForensicService() {
        val intent = Intent(this, ForensicService::class.java)
        startForegroundService(intent)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContainer(viewModel: ForensicViewModel) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var selectedEvent by remember { mutableStateOf<ForensicEvent?>(null) }
    var showSheet by remember { mutableStateOf(false) }
    val context = LocalContext.current

    LaunchedEffect(Unit) {
        viewModel.syncStatus.collect { message ->
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("SENTRY RADIO", fontWeight = FontWeight.ExtraBold, letterSpacing = 2.sp) },
                actions = {
                    IconButton(onClick = {
                        viewModel.exportLogsToPcap(context)
                        Toast.makeText(context, "Exporting GSMTAP PCAP...", Toast.LENGTH_SHORT).show()
                    }) {
                        Icon(Icons.Default.Build, contentDescription = "PCAP Export", tint = Color.Cyan)
                    }
                    IconButton(onClick = { viewModel.clearLogs() }) {
                        Icon(Icons.Default.Delete, contentDescription = "Clear", tint = Color.Red)
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = Color(0xFF121212),
                    titleContentColor = Color.White
                )
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF121212)) {
                NavigationItem("Status", Icons.Default.Home, selectedTab == 0) { selectedTab = 0 }
                NavigationItem("Map", Icons.Default.Place, selectedTab == 1) { selectedTab = 1 }
                NavigationItem("Audit", Icons.AutoMirrored.Filled.List, selectedTab == 2) { selectedTab = 2 }
                NavigationItem("Analytics", Icons.Default.Info, selectedTab == 3) { selectedTab = 3 }
                NavigationItem("Settings", Icons.Default.Settings, selectedTab == 4) { selectedTab = 4 }
            }
        }
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding).fillMaxSize().background(Color.Black)) {
            when (selectedTab) {
                0 -> DashboardScreen(viewModel)
                1 -> MapForensicScreen(viewModel)
                2 -> TimelineScreen(viewModel) { event ->
                    selectedEvent = event
                    showSheet = true
                }
                3 -> AdvancedAnalyticsScreen(viewModel)
                4 -> SettingsScreen(viewModel)
            }
        }

        if (showSheet && selectedEvent != null) {
            ModalBottomSheet(
                onDismissRequest = { showSheet = false },
                containerColor = Color(0xFF1E1E1E),
                contentColor = Color.White,
                dragHandle = { BottomSheetDefaults.DragHandle(color = Color.Gray) }
            ) {
                ForensicDetailView(selectedEvent!!, viewModel)
            }
        }
    }
}

@Composable
fun RowScope.NavigationItem(label: String, icon: ImageVector, selected: Boolean, onClick: () -> Unit) {
    NavigationBarItem(
        selected = selected,
        onClick = onClick,
        icon = { Icon(icon, contentDescription = label) },
        label = { Text(label) },
        colors = NavigationBarItemDefaults.colors(
            selectedIconColor = Color.Cyan,
            unselectedIconColor = Color.Gray,
            indicatorColor = Color(0xFF1E1E1E)
        )
    )
}

@Composable
fun DashboardScreen(viewModel: ForensicViewModel) {
    val state by viewModel.dashboardState.collectAsState()
    val alertBrush = Brush.verticalGradient(listOf(Color(0xFF420000), Color.Black))
    val scrollState = rememberScrollState()

    Column(Modifier.fillMaxSize().verticalScroll(scrollState)) {
        TabRow(
            selectedTabIndex = state.activeSimSlot,
            containerColor = Color(0xFF121212),
            contentColor = Color.Cyan,
            divider = {},
            indicator = { tabPositions ->
                TabRowDefaults.SecondaryIndicator(
                    Modifier.tabIndicatorOffset(tabPositions[state.activeSimSlot]),
                    color = Color.Cyan
                )
            }
        ) {
            Tab(selected = state.activeSimSlot == 0, onClick = { viewModel.setActiveSimSlot(0) }) {
                Text("SIM 1", modifier = Modifier.padding(16.dp), color = if(state.activeSimSlot == 0) Color.Cyan else Color.Gray)
            }
            Tab(selected = state.activeSimSlot == 1, onClick = { viewModel.setActiveSimSlot(1) }) {
                Text("SIM 2", modifier = Modifier.padding(16.dp), color = if(state.activeSimSlot == 1) Color.Cyan else Color.Gray)
            }
        }

        val activeSim = if(state.activeSimSlot == 0) state.sim0 else state.sim1

        Column(Modifier.padding(16.dp)) {
            Box(modifier = Modifier.fillMaxWidth()) {
                ThreatGauge(state.threatLevel, state.securityStatus)

                IconButton(
                    onClick = {},
                    modifier = Modifier.align(Alignment.TopEnd).padding(16.dp)
                ) {
                    Icon(
                        imageVector = if (activeSim.isCipheringActive) Icons.Default.Lock else Icons.Default.Warning,
                        contentDescription = "Encryption Status",
                        tint = if (activeSim.isCipheringActive) Color.Green else Color.Red,
                        modifier = Modifier.size(32.dp)
                    )
                }
            }

            Spacer(Modifier.height(16.dp))
            SignalChart(activeSim.rssiHistory)
            Spacer(Modifier.height(16.dp))

            AnimatedVisibility(
                visible = state.activeThreats.isNotEmpty(),
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.Transparent)
                ) {
                    Column(Modifier.background(alertBrush).padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = Color.Red)
                            Spacer(Modifier.width(8.dp))
                            Text("ACTIVE THREATS DETECTED", fontWeight = FontWeight.Black, color = Color.Red, fontSize = 14.sp)
                        }
                        Spacer(Modifier.height(8.dp))
                        state.activeThreats.forEach { threat ->
                            Text("• $threat", color = Color.White, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }

            val signalColor = when {
                activeSim.signalStrength > -55 -> Color.Red
                activeSim.signalStrength > -85 -> Color.Cyan
                activeSim.signalStrength > -105 -> Color.Yellow
                else -> Color.Gray
            }

            Text("RADIO STACK PARAMETERS", color = Color.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
            
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MetricCard("PCI (Physical Cell ID)", activeSim.pci, Modifier.weight(1f))
                MetricCard("EARFCN / ARFCN", activeSim.earfcn, Modifier.weight(1f))
            }
            Spacer(Modifier.height(12.dp))
            MetricCard("Active Sector / Cell ID", activeSim.currentCellId, Modifier.fillMaxWidth())
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MetricCard("LAC / TAC", if (activeSim.lac != "---") activeSim.lac else activeSim.tac, Modifier.weight(1f))
                MetricCard("Network Type", activeSim.networkType, Modifier.weight(1f))
            }
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MetricCard("Signal Power", "${activeSim.signalStrength} dBm", Modifier.weight(1f), signalColor)
                MetricCard("Detected Neighbors", activeSim.neighborCount.toString(), Modifier.weight(1f))
            }
            
            Spacer(Modifier.height(24.dp))
            Text("OPERATOR INFO", color = Color.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MetricCard("MCC", activeSim.mcc, Modifier.weight(1f))
                MetricCard("MNC", activeSim.mnc, Modifier.weight(1f))
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
fun SignalChart(history: List<Int>) {
    Card(
        modifier = Modifier.fillMaxWidth().height(100.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF121212)),
        border = BorderStroke(1.dp, Color.DarkGray)
    ) {
        Column(Modifier.padding(8.dp)) {
            Text("SIGNAL STABILITY (LIVE)", color = Color.Gray, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Canvas(modifier = Modifier.fillMaxSize()) {
                if (history.isEmpty()) return@Canvas

                val path = Path()
                val stepX = if (history.size > 1) size.width / (history.size - 1) else size.width
                val minSignal = -120f
                val maxSignal = -40f
                val range = maxSignal - minSignal

                history.forEachIndexed { index, dbm ->
                    val x = index * stepX
                    val normalizedY = (dbm.toFloat().coerceIn(minSignal, maxSignal) - minSignal) / range
                    val y = size.height - (normalizedY * size.height)

                    if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
                    drawCircle(Color.Cyan.copy(alpha = 0.5f), radius = 2.dp.toPx(), center = Offset(x, y))
                }

                val lastSignal = history.lastOrNull() ?: -120
                val lineColor = when {
                    lastSignal > -55 -> Color.Red
                    lastSignal > -85 -> Color.Cyan
                    lastSignal > -105 -> Color.Yellow
                    else -> Color.Gray
                }

                if (history.size > 1) {
                    drawPath(path, lineColor, style = Stroke(width = 2.dp.toPx()))
                }
            }
        }
    }
}

@Composable
fun SettingsScreen(viewModel: ForensicViewModel) {
    val settings by viewModel.settings.collectAsState()
    val dashboardState by viewModel.dashboardState.collectAsState()

    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("SYSTEM SETTINGS", fontWeight = FontWeight.Black, color = Color.Cyan, fontSize = 18.sp)
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusIndicator("ROOT", dashboardState.hasRoot, Modifier.weight(1f))
                StatusIndicator("XPOSED", dashboardState.isXposedActive, Modifier.weight(1f))
            }
            Spacer(Modifier.height(24.dp))
        }

        item {
            Text("API CONFIGURATION", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(16.dp))
            
            SettingsRow("BeaconDB (No Key)", "Public crowdsourced database", settings.useBeaconDb) {
                viewModel.updateUseBeaconDb(it)
            }
            Spacer(Modifier.height(16.dp))

            SettingsRow("OpenCellID", "World's largest open cell database", settings.useOpenCellId) {
                viewModel.updateUseOpenCellId(it)
            }
            OutlinedTextField(
                value = settings.openCellIdKey,
                onValueChange = { viewModel.updateOpenCellIdKey(it) },
                label = { Text("OpenCellID API Key") },
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                singleLine = true,
                enabled = settings.useOpenCellId,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedBorderColor = Color.Cyan,
                    unfocusedBorderColor = Color.Gray
                )
            )
            Spacer(Modifier.height(16.dp))

            SettingsRow("Unwired Labs", "Precise cell geolocation API", settings.useUnwiredLabs) {
                viewModel.updateUseUnwiredLabs(it)
            }
            OutlinedTextField(
                value = settings.unwiredLabsKey,
                onValueChange = { viewModel.updateUnwiredLabsKey(it) },
                label = { Text("Unwired Labs API Key") },
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                singleLine = true,
                enabled = settings.useUnwiredLabs,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedBorderColor = Color.Cyan,
                    unfocusedBorderColor = Color.Gray
                )
            )
            Text("API keys required for live verification.", color = Color.Gray, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            Spacer(Modifier.height(24.dp))
        }

        item {
            Text("LOGGING OPTIONS", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))
            SettingsRow("LOG RADIO METRICS", "Capture and log signal metrics", settings.logRadioMetrics) {
                viewModel.updateLogRadioMetrics(it)
            }
            Spacer(Modifier.height(12.dp))
            SettingsRow("SUSPICIOUS EVENTS", "Show possible IMSI Catcher alerts", settings.logSuspiciousEvents) {
                viewModel.updateLogSuspiciousEvents(it)
            }
            Spacer(Modifier.height(12.dp))
            SettingsRow("LOG ROOT SIGNAL FEED", "Show root engine updates in audit", settings.logRootFeed) {
                viewModel.updateLogRootFeed(it)
            }
            Spacer(Modifier.height(12.dp))
            SettingsRow("SHOW BLOCKED EVENTS", "View logs from blocked cell IDs", settings.showBlockedEvents) {
                viewModel.updateShowBlockedEvents(it)
            }
            Spacer(Modifier.height(24.dp))
        }

        item {
            Text("PROTECTION SENSITIVITY", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Slider(
                value = settings.sensitivity.toFloat(),
                onValueChange = { viewModel.updateSensitivity(it.toInt()) },
                valueRange = 0f..2f,
                steps = 1,
                colors = SliderDefaults.colors(thumbColor = Color.Cyan, activeTrackColor = Color.Cyan)
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Low", color = Color.Gray, fontSize = 12.sp)
                Text("Medium", color = Color.Gray, fontSize = 12.sp)
                Text("High", color = Color.Gray, fontSize = 12.sp)
            }
            Spacer(Modifier.height(24.dp))
        }

        item {
            Text("CELL BLOCK MANAGEMENT", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { viewModel.unblockAllCells() },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color.DarkGray)
                ) {
                    Text("UNBLOCK ALL", fontSize = 10.sp)
                }
                Button(
                    onClick = { viewModel.deleteBlockedLogs() },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF420000))
                ) {
                    Text("DELETE BLOCKED", fontSize = 10.sp, color = Color.Red)
                }
            }
        }

        item {
            Spacer(Modifier.height(48.dp))
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "Developer: fzer0x | Version: 0.1.0-beta",
                    color = Color.Gray,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
fun SettingsRow(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Column(Modifier.weight(1f)) {
            Text(title, color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Text(subtitle, color = Color.Gray, fontSize = 11.sp)
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(checkedThumbColor = Color.Cyan, checkedTrackColor = Color.Cyan.copy(alpha = 0.5f))
        )
    }
}

@Composable
fun StatusIndicator(label: String, active: Boolean, modifier: Modifier) {
    val color = if (active) Color.Green else Color.Red
    Card(modifier, colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).background(color, CircleShape))
            Spacer(Modifier.width(8.dp))
            Text(label, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.weight(1f))
            Text(if (active) "OK" else "OFF", color = color, fontSize = 10.sp, fontWeight = FontWeight.Black)
        }
    }
}

@Composable
fun MapForensicScreen(viewModel: ForensicViewModel) {
    val context = LocalContext.current
    val towers by viewModel.allTowers.collectAsState()
    val lifecycleOwner = LocalLifecycleOwner.current

    val mapView = remember {
        MapView(context).apply {
            setTileSource(TileSourceFactory.MAPNIK)
            setMultiTouchControls(true)
            isTilesScaledToDpi = true
            controller.setZoom(15.0)
        }
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> mapView.onResume()
                Lifecycle.Event.ON_PAUSE -> mapView.onPause()
                else -> {}
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            mapView.onDetach()
        }
    }

    Box(Modifier.fillMaxSize()) {
        AndroidView(
            factory = { mapView },
            modifier = Modifier.fillMaxSize(),
            update = { view ->
                view.overlays.removeAll { it is Marker || it is Polyline || it is Polygon }

                val points = mutableListOf<GeoPoint>()
                towers.filter { it.latitude != null && it.longitude != null }
                    .sortedBy { it.firstSeen }
                    .forEach { tower ->
                        val point = GeoPoint(tower.latitude!!, tower.longitude!!)
                        points.add(point)

                        tower.range?.let { r ->
                            val circle = Polygon(view)
                            circle.points = Polygon.pointsAsCircle(point, r)
                            val color = when {
                                tower.isBlocked -> android.graphics.Color.argb(80, 50, 50, 50) 
                                tower.isMissingInDb -> android.graphics.Color.argb(80, 255, 0, 0) 
                                tower.changeable == false -> android.graphics.Color.argb(40, 0, 255, 0) 
                                tower.isVerified -> android.graphics.Color.argb(40, 0, 255, 255) 
                                else -> android.graphics.Color.argb(40, 255, 255, 0) 
                            }
                            circle.fillPaint.color = color
                            circle.outlinePaint.color = color
                            circle.outlinePaint.strokeWidth = 2f
                            
                            circle.setOnClickListener { _, _, _ -> true }
                            
                            view.overlays.add(circle)
                        }

                        val marker = Marker(view)
                        marker.position = point
                        marker.title = "Cell ID: ${tower.cellId}${if(tower.isBlocked) " (BLOCKED)" else ""}"

                        val verificationType = when {
                            tower.isBlocked -> "ADMIN: BLOCKED"
                            tower.isMissingInDb -> "CRITICAL: NOT IN DATABASE"
                            tower.isVerified && tower.changeable == false -> "PRECISE (DB)"
                            tower.isVerified -> "CALCULATED (DB)"
                            else -> "APPROX (GPS)"
                        }

                        marker.snippet = """
                            Type: ${tower.rat}
                            MCC/MNC: ${tower.mcc}/${tower.mnc}
                            LAC/TAC: ${tower.lac}
                            Verification: $verificationType
                            Range: ${tower.range?.toInt() ?: "N/A"}m
                            Samples: ${tower.samples ?: "N/A"}
                        """.trimIndent()

                        val iconRes = when {
                            tower.isBlocked -> android.R.drawable.ic_lock_power_off
                            tower.isMissingInDb -> android.R.drawable.ic_delete 
                            tower.isVerified && tower.changeable == false -> android.R.drawable.ic_dialog_map 
                            tower.isVerified -> android.R.drawable.ic_menu_mylocation 
                            else -> android.R.drawable.presence_invisible 
                        }

                        marker.icon = ContextCompat.getDrawable(context, iconRes)
                        marker.setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_BOTTOM)
                        
                        marker.setOnMarkerClickListener { m, _ ->
                            if (!m.title.isNullOrBlank()) {
                                m.showInfoWindow()
                            }
                            true
                        }
                        
                        view.overlays.add(marker)
                    }

                if (points.size >= 2) {
                    val line = Polyline(view)
                    line.setPoints(points)
                    line.outlinePaint.color = android.graphics.Color.CYAN
                    line.outlinePaint.strokeWidth = 5f
                    line.setOnClickListener { _, _, _ -> true }
                    view.overlays.add(line)
                }

                if (view.overlays.none { it is MyLocationNewOverlay }) {
                    val locationOverlay = MyLocationNewOverlay(GpsMyLocationProvider(context), view)
                    locationOverlay.enableMyLocation()
                    locationOverlay.enableFollowLocation()
                    view.overlays.add(locationOverlay)
                }

                view.invalidate()
            }
        )

        Column(
            modifier = Modifier.align(Alignment.BottomEnd).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            FloatingActionButton(
                onClick = {
                    viewModel.refreshTowerLocations()
                    Toast.makeText(context, "Scanning for tower locations...", Toast.LENGTH_SHORT).show()
                },
                containerColor = Color.Yellow,
                contentColor = Color.Black
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Sync API")
            }

            FloatingActionButton(
                onClick = {
                    val locationOverlay = mapView.overlays.filterIsInstance<MyLocationNewOverlay>().firstOrNull()
                    locationOverlay?.myLocation?.let { geoPoint ->
                        mapView.controller.animateTo(geoPoint)
                        mapView.controller.setZoom(18.0)
                    } ?: run {
                        towers.firstOrNull { it.latitude != null }?.let { t ->
                            mapView.controller.animateTo(GeoPoint(t.latitude!!, t.longitude!!))
                            mapView.controller.setZoom(15.0)
                        }
                    }
                },
                containerColor = Color.Cyan,
                contentColor = Color.Black
            ) {
                Icon(Icons.Default.Place, contentDescription = "Zoom")
            }
        }
    }
}

@Composable
fun ThreatGauge(level: Int, status: String) {
    val color = when {
        level >= 90 -> Color.Red
        level > 40 -> Color.Yellow
        else -> Color.Cyan
    }
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Box(Modifier.size(120.dp).clip(CircleShape).background(color.copy(alpha = 0.1f)), contentAlignment = Alignment.Center) {
                Text("$level", fontSize = 48.sp, fontWeight = FontWeight.Black, color = color)
            }
            Spacer(Modifier.height(16.dp))
            Text(status.uppercase(), color = color, fontWeight = FontWeight.Black, style = MaterialTheme.typography.titleMedium, letterSpacing = 1.sp)
        }
    }
}

@Composable
fun MetricCard(label: String, value: String, modifier: Modifier, valueColor: Color = Color.White) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))) {
        Column(Modifier.padding(16.dp)) {
            Text(label, color = Color.Gray, style = MaterialTheme.typography.labelSmall)
            Text(value, color = valueColor, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
fun AdvancedAnalyticsScreen(viewModel: ForensicViewModel) {
    val state by viewModel.dashboardState.collectAsState()
    val logs by viewModel.allLogs.collectAsState()
    val scrollState = rememberScrollState()

    Column(Modifier.fillMaxSize().verticalScroll(scrollState)) {
        TabRow(
            selectedTabIndex = state.activeSimSlot,
            containerColor = Color(0xFF121212),
            contentColor = Color.Cyan,
            divider = {},
            indicator = { tabPositions ->
                TabRowDefaults.SecondaryIndicator(
                    Modifier.tabIndicatorOffset(tabPositions[state.activeSimSlot]),
                    color = Color.Cyan
                )
            }
        ) {
            Tab(selected = state.activeSimSlot == 0, onClick = { viewModel.setActiveSimSlot(0) }) {
                Text("SIM 1", modifier = Modifier.padding(16.dp), color = if(state.activeSimSlot == 0) Color.Cyan else Color.Gray)
            }
            Tab(selected = state.activeSimSlot == 1, onClick = { viewModel.setActiveSimSlot(1) }) {
                Text("SIM 2", modifier = Modifier.padding(16.dp), color = if(state.activeSimSlot == 1) Color.Cyan else Color.Gray)
            }
        }

        val simLogs = logs.filter { it.simSlot == state.activeSimSlot }

        Column(Modifier.padding(16.dp)) {
            Text("THREAT OVERVIEW", color = Color.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
            ThreatSummaryCard(simLogs)
            
            Spacer(Modifier.height(24.dp))
            Text("SIGNAL & MODEM ANALYSIS", color = Color.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
            SignalAnalysisCard(simLogs)
            Spacer(Modifier.height(12.dp))
            BasebandAnalysisCard(simLogs)
            
            Spacer(Modifier.height(24.dp))
            Text("PROTOCOL & MOBILITY", color = Color.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
            RrcStateAnalysisCard(simLogs)
            Spacer(Modifier.height(12.dp))
            HandoverAnalysisCard(simLogs)
            
            Spacer(Modifier.height(24.dp))
            Text("NETWORK INTEGRITY", color = Color.Cyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
            NetworkCapabilityCard(simLogs)
            
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
fun SignalAnalysisCard(logs: List<ForensicEvent>) {
    val signalAnomalies = logs.filter { it.type.name == "SIGNAL_ANOMALY" || it.type.name == "TIMING_ADVANCE_ANOMALY" }
    val interferences = logs.filter { it.type.name == "INTERFERENCE_DETECTED" }
    val signalStrengths = logs.mapNotNull { it.signalStrength }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Settings, contentDescription = null, tint = Color.Cyan, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("SIGNAL ANALYSIS", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }

            Spacer(Modifier.height(12.dp))

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AnalyticsMetric("Anomalies", signalAnomalies.size.toString(), Color.Red, Modifier.weight(1f))
                AnalyticsMetric("Interference", interferences.size.toString(), Color.Yellow, Modifier.weight(1f))
                AnalyticsMetric("Avg Signal",
                    if (signalStrengths.isNotEmpty()) "${signalStrengths.average().toInt()}dBm" else "N/A",
                    Color.Green, Modifier.weight(1f))
            }

            if (signalAnomalies.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Text("Detected Issues:", color = Color.Yellow, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                signalAnomalies.take(3).forEach { event ->
                    Text("• ${event.description.take(50)}...", color = Color.Red, fontSize = 10.sp)
                }
            }
        }
    }
}

@Composable
fun BasebandAnalysisCard(logs: List<ForensicEvent>) {
    val vulnerableBasebands = logs.filter { it.type.name == "VULNERABLE_BASEBAND" }
    val hasBasebandData = logs.any { it.basebandVersion != null }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Build, contentDescription = null, tint = Color.Yellow, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("BASEBAND FINGERPRINTING", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }

            Spacer(Modifier.height(12.dp))

            if (vulnerableBasebands.isNotEmpty()) {
                vulnerableBasebands.take(2).forEach { event ->
                    Text(event.description, color = Color.Red, fontSize = 11.sp)
                }
            } else if (hasBasebandData) {
                Text("Device baseband monitored - No known vulnerabilities", color = Color.Green, fontSize = 11.sp)
            } else {
                Text("Baseband data not yet available", color = Color.Gray, fontSize = 11.sp)
            }
        }
    }
}

@Composable
fun RrcStateAnalysisCard(logs: List<ForensicEvent>) {
    val rrcChanges = logs.filter { it.type.name == "RRC_STATE_CHANGE" }
    val rrcAnomalies = logs.filter { it.type.name == "RRC_ANOMALY" }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Settings, contentDescription = null, tint = Color.Magenta, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("RRC STATE TRACKING", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }

            Spacer(Modifier.height(12.dp))

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AnalyticsMetric("State Changes", rrcChanges.size.toString(), Color.Magenta, Modifier.weight(1f))
                AnalyticsMetric("Anomalies", rrcAnomalies.size.toString(),
                    if (rrcAnomalies.isNotEmpty()) Color.Red else Color.Green,
                    Modifier.weight(1f))
            }
        }
    }
}

@Composable
fun HandoverAnalysisCard(logs: List<ForensicEvent>) {
    val handoverAnomalies = logs.filter { it.type.name == "HANDOVER_ANOMALY" }
    val pingPongEvents = logs.filter { it.type.name == "HANDOVER_PINGPONG" }
    val totalHandovers = logs.filter { it.description.contains("handover", ignoreCase = true) }.size

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Refresh, contentDescription = null, tint = Color.Blue, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("HANDOVER DETECTION", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }

            Spacer(Modifier.height(12.dp))

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AnalyticsMetric("Total", totalHandovers.toString(), Color.Blue, Modifier.weight(1f))
                AnalyticsMetric("Anomalies", handoverAnomalies.size.toString(), Color.Yellow, Modifier.weight(1f))
                AnalyticsMetric("Ping-Pong", pingPongEvents.size.toString(),
                    if (pingPongEvents.isNotEmpty()) Color.Red else Color.Green,
                    Modifier.weight(1f))
            }
        }
    }
}

@Composable
fun NetworkCapabilityCard(logs: List<ForensicEvent>) {
    val degradations = logs.filter { it.type.name == "NETWORK_DEGRADATION" || it.type.name == "CELL_DOWNGRADE" }
    val legacyWarnings = logs.filter { it.type.name == "LEGACY_NETWORK" }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Info, contentDescription = null, tint = Color.Green, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("NETWORK CAPABILITY", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }

            Spacer(Modifier.height(12.dp))

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AnalyticsMetric("Degradations", degradations.size.toString(),
                    if (degradations.isNotEmpty()) Color.Red else Color.Green,
                    Modifier.weight(1f))
                AnalyticsMetric("Legacy Warnings", legacyWarnings.size.toString(), Color.Yellow, Modifier.weight(1f))
            }
        }
    }
}

@Composable
fun ThreatSummaryCard(logs: List<ForensicEvent>) {
    val signalThreats = logs.filter { it.type.name in listOf("SIGNAL_ANOMALY", "INTERFERENCE_DETECTED", "TIMING_ADVANCE_ANOMALY") }.size
    val basebandThreats = logs.filter { it.type.name == "VULNERABLE_BASEBAND" }.size
    val rrcThreats = logs.filter { it.type.name in listOf("RRC_STATE_CHANGE", "RRC_ANOMALY") }.size
    val handoverThreats = logs.filter { it.type.name in listOf("HANDOVER_ANOMALY", "HANDOVER_PINGPONG") }.size
    val networkThreats = logs.filter { it.type.name in listOf("NETWORK_DEGRADATION", "LEGACY_NETWORK", "CELL_DOWNGRADE") }.size

    val totalThreats = signalThreats + basebandThreats + rrcThreats + handoverThreats + networkThreats
    val threatColor = when {
        totalThreats > 10 -> Color.Red
        totalThreats > 5 -> Color.Yellow
        totalThreats > 0 -> Color.Magenta
        else -> Color.Green
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = threatColor, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("THREAT SUMMARY", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text("Analytics Coverage", color = Color.Gray, fontSize = 10.sp)
                }
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(threatColor.copy(alpha = 0.1f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(totalThreats.toString(), color = threatColor, fontWeight = FontWeight.Black, fontSize = 18.sp)
                }
            }

            Spacer(Modifier.height(16.dp))

            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                ThreatBreakdownRow("Signal Anomalies", signalThreats, Color.Cyan)
                ThreatBreakdownRow("Baseband Issues", basebandThreats, Color.Yellow)
                ThreatBreakdownRow("RRC Anomalies", rrcThreats, Color.Magenta)
                ThreatBreakdownRow("Handover Issues", handoverThreats, Color.Blue)
                ThreatBreakdownRow("Network Threats", networkThreats, Color.Red)
            }
        }
    }
}

@Composable
fun ThreatBreakdownRow(label: String, count: Int, color: Color) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Color.Gray, fontSize = 11.sp)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(6.dp).background(color, CircleShape))
            Spacer(Modifier.width(8.dp))
            Text(count.toString(), color = color, fontWeight = FontWeight.Bold, fontSize = 11.sp)
        }
    }
}

@Composable
fun AnalyticsMetric(label: String, value: String, color: Color, modifier: Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Color(0xFF121212))
    ) {
        Column(
            Modifier
                .padding(12.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(label, color = Color.Gray, fontSize = 10.sp)
            Text(value, color = color, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        }
    }
}

@Composable
fun TimelineScreen(viewModel: ForensicViewModel, onEventClick: (ForensicEvent) -> Unit) {
    val logs by viewModel.allLogs.collectAsState()
    val blockedIds by viewModel.blockedCellIds.collectAsState()
    val dateFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    LazyColumn(Modifier.fillMaxSize().padding(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(logs) { log ->
            val isCritical = log.severity >= 8
            val isBlocked = log.cellId != null && blockedIds.contains(log.cellId)
            
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onEventClick(log) },
                colors = CardDefaults.cardColors(
                    containerColor = when {
                        isBlocked -> Color(0xFF121212)
                        isCritical -> Color(0xFF330000)
                        else -> Color(0xFF1E1E1E)
                    }
                ),
                border = when {
                    isBlocked -> BorderStroke(1.dp, Color.Gray)
                    isCritical -> BorderStroke(2.dp, Color.Red)
                    else -> null
                }
            ) {
                ListItem(
                    headlineContent = {
                        Text(log.description + if(isBlocked) " (BLOCKED)" else "",
                            color = when {
                                isBlocked -> Color.Gray
                                isCritical -> Color.Red
                                else -> Color.White
                            },
                            fontWeight = if(isCritical) FontWeight.Bold else FontWeight.Normal
                        )
                    },
                    supportingContent = { Text("SIM ${log.simSlot + 1} • ${log.type} • ${dateFormat.format(Date(log.timestamp))}", color = Color.Gray) },
                    trailingContent = { 
                        Icon(
                            imageVector = if(isBlocked) Icons.Default.Lock else Icons.Default.Info, 
                            contentDescription = null, 
                            tint = if(isBlocked) Color.Gray else if(isCritical) Color.Red else Color.Gray
                        ) 
                    },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent)
                )
            }
        }
    }
}

@Composable
fun ForensicDetailView(event: ForensicEvent, viewModel: ForensicViewModel) {
    val scrollState = rememberScrollState()
    val blockedIds by viewModel.blockedCellIds.collectAsState()
    val isBlocked = event.cellId != null && blockedIds.contains(event.cellId)
    
    Column(Modifier.fillMaxWidth().verticalScroll(scrollState).padding(24.dp).navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Detailed Analysis", style = MaterialTheme.typography.headlineSmall, color = Color.Cyan, fontWeight = FontWeight.Bold)
            
            if (event.cellId != null) {
                Button(
                    onClick = { viewModel.toggleBlockCell(event.cellId) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if(isBlocked) Color.Gray else Color(0xFF420000),
                        contentColor = if(isBlocked) Color.Black else Color.White
                    ),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    modifier = Modifier.height(32.dp)
                ) {
                    Icon(if(isBlocked) Icons.Default.Check else Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (isBlocked) "UNBLOCK" else "BLOCK CELL", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp), color = Color.Gray.copy(alpha = 0.5f))

        DetailRow("SIM Slot", "SIM ${event.simSlot + 1}")
        DetailRow("Type", event.type.name)
        DetailRow("Severity", "${event.severity}/10")
        DetailRow("Timestamp", SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date(event.timestamp)))
        DetailRow("Cell Identity", event.cellId ?: "N/A")
        DetailRow("PCI / EARFCN", "${event.pci ?: "N/A"} / ${event.earfcn ?: "N/A"}")
        DetailRow("MCC/MNC", "${event.mcc ?: "---"}/${event.mnc ?: "---"}")
        DetailRow("Signal Strength", "${event.signalStrength ?: "N/A"} dBm")
        DetailRow("Timing Advance", "${event.timingAdvance ?: "N/A"}")
        DetailRow("Neighbors", "${event.neighborCount ?: "N/A"}")

        if (!event.rawData.isNullOrBlank()) {
            Spacer(Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("RAW LOGCAT CAPTURE:", color = Color.Yellow, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                val clipboardManager = LocalClipboardManager.current
                IconButton(
                    onClick = { clipboardManager.setText(AnnotatedString(event.rawData!!)) },
                    modifier = Modifier.size(24.dp)
                ) {
                    Icon(Icons.Default.Share, contentDescription = "Copy", tint = Color.Cyan, modifier = Modifier.size(16.dp))
                }
            }

            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 400.dp)
                    .padding(top = 8.dp),
                color = Color.Black,
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, Color.Gray.copy(alpha = 0.3f))
            ) {
                val internalScrollState = rememberScrollState()
                SelectionContainer {
                    Text(
                        text = event.rawData!!,
                        modifier = Modifier
                            .padding(12.dp)
                            .verticalScroll(internalScrollState),
                        color = Color.Green,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        if (event.severity >= 8) {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF420000))) {
                Text("CRITICAL ANOMALY: This event matches high-confidence IMSI Catcher patterns.", Modifier.padding(16.dp), color = Color.Red, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Color.Gray)
        Text(value, color = Color.White, fontWeight = FontWeight.Bold)
    }
}
