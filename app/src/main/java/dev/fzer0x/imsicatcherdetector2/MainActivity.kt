package dev.fzer0x.imsicatcherdetector2

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
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
import androidx.compose.foundation.Canvas as ComposeCanvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
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
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import dev.fzer0x.imsicatcherdetector2.data.ForensicEvent
import dev.fzer0x.imsicatcherdetector2.service.ForensicService
import dev.fzer0x.imsicatcherdetector2.ui.theme.IMSICatcherDetector2Theme
import dev.fzer0x.imsicatcherdetector2.ui.viewmodel.ForensicViewModel
import dev.fzer0x.imsicatcherdetector2.security.VulnerabilityManager
import dev.fzer0x.imsicatcherdetector2.security.UpdateManager
import dev.fzer0x.imsicatcherdetector2.ui.components.UpdateDialog
import dev.fzer0x.imsicatcherdetector2.ui.components.CveListDialog
import dev.fzer0x.imsicatcherdetector2.utils.VersionUtils
import kotlinx.coroutines.delay
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
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import org.osmdroid.events.MapEventsReceiver
import org.osmdroid.views.overlay.MapEventsOverlay
import org.osmdroid.views.overlay.OverlayWithIW

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
        
        // Update Check mit dynamischer Version
        val currentVersion = VersionUtils.getCurrentVersion(this)
        UpdateManager.setUpdateCallback(object : UpdateManager.UpdateCallback {
            override fun onUpdateAvailable(currentVersion: String, latestVersion: String) {
                // Update-Dialog wird in der UI angezeigt
            }
        })
        UpdateManager.checkForUpdates(this, currentVersion)
        
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
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
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

    fun requestOverlayPermission() {
        if (!Settings.canDrawOverlays(this)) {
            val intent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName")
            )
            startActivity(intent)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContainer(viewModel: ForensicViewModel) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var selectedEvent by remember { mutableStateOf<ForensicEvent?>(null) }
    var showSheet by remember { mutableStateOf(false) }
    var showUpdateDialog by remember { mutableStateOf(false) }
    var showCveDialog by remember { mutableStateOf(false) }
    var showRebootDialog by remember { mutableStateOf(false) }
    var currentVersion by remember { mutableStateOf("0-0.0.0") }
    var latestVersion by remember { mutableStateOf("0-0.0.0") }
    val context = LocalContext.current as MainActivity

    // Update-Callback setzen
    LaunchedEffect(Unit) {
        UpdateManager.setUpdateCallback(object : UpdateManager.UpdateCallback {
            override fun onUpdateAvailable(current: String, latest: String) {
                currentVersion = current
                latestVersion = latest
                showUpdateDialog = true
            }
        })
        
        // Update-Check durchführen
        val version = VersionUtils.getCurrentVersion(context)
        currentVersion = version
        UpdateManager.checkForUpdates(context, version)
    }

    LaunchedEffect(Unit) {
        viewModel.syncStatus.collect { message ->
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
            // Show reboot dialog only when installation is actually completed successfully
            if (message == "Installation successful! Reboot required.") {
                // Small delay to ensure the installation toast is seen first
                kotlinx.coroutines.delay(5000)
                showRebootDialog = true
            }
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
                NavigationItem("Security", Icons.Default.Lock, selectedTab == 3) { selectedTab = 3 }
                NavigationItem("Analytic", Icons.Default.Info, selectedTab == 4) { selectedTab = 4 }
                NavigationItem("Settings", Icons.Default.Settings, selectedTab == 5) { selectedTab = 5 }
            }
        }
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding).fillMaxSize().background(Color.Black)) {
            Column {
                // Overlay Permission Warning
                var hasOverlayPermission by remember { mutableStateOf(Settings.canDrawOverlays(context)) }

                val lifecycleOwner = LocalLifecycleOwner.current
                DisposableEffect(lifecycleOwner) {
                    val observer = LifecycleEventObserver { _, event ->
                        if (event == Lifecycle.Event.ON_RESUME) {
                            hasOverlayPermission = Settings.canDrawOverlays(context)
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
                }

                if (!hasOverlayPermission) {
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(8.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF420000)),
                        border = BorderStroke(1.dp, Color.Red)
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = Color.Red)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text("OVERLAY PERMISSION MISSING", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                Text("Required to show alarm over other apps.", color = Color.Gray, fontSize = 10.sp)
                            }
                            Button(
                                onClick = { context.requestOverlayPermission() },
                                colors = ButtonDefaults.buttonColors(containerColor = Color.Red),
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text("GRANT", fontSize = 10.sp)
                            }
                        }
                    }
                }

                Box(modifier = Modifier.weight(1f)) {
                    when (selectedTab) {
                        0 -> DashboardScreen(viewModel, { showCveDialog = true }) { selectedTab = 5 }
                        1 -> MapForensicScreen(viewModel)
                        2 -> TimelineScreen(viewModel) { event ->
                            selectedEvent = event
                            showSheet = true
                        }
                        3 -> SecurityScreen(viewModel)
                        4 -> AdvancedAnalyticsScreen(viewModel)
                        5 -> SettingsScreen(viewModel)
                    }
                }
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
        
        // Update Dialog
        if (showUpdateDialog) {
            UpdateDialog(
                currentVersion = currentVersion,
                latestVersion = latestVersion,
                onDismiss = { showUpdateDialog = false }
            )
        }
        
        // CVE Dialog
        if (showCveDialog) {
            val state = viewModel.dashboardState.collectAsState().value
            CveListDialog(
                vulnerabilities = state.vulnerabilities,
                chipset = state.detectedChipset,
                baseband = state.detectedBaseband,
                securityPatch = state.securityPatch,
                onDismiss = { showCveDialog = false }
            )
        }
        
        // Reboot Dialog
        if (showRebootDialog) {
            RebootDialog(
                onDismiss = { showRebootDialog = false },
                onReboot = { 
                    showRebootDialog = false
                    // Trigger system reboot
                    try {
                        val powerManager = context.getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
                        powerManager.reboot("Sentry Radio Module Installation")
                    } catch (e: Exception) {
                        // Fallback for devices that don't allow app reboot
                        val intent = Intent(Intent.ACTION_REBOOT)
                        intent.putExtra("now", "now")
                        intent.putExtra("interval", 1)
                        intent.putExtra("window", 0)
                        context.sendBroadcast(intent)
                    }
                }
            )
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
fun DashboardScreen(viewModel: ForensicViewModel, onShowCveDialog: () -> Unit, onNavigateToSettings: () -> Unit) {
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
                if (state.activeSimSlot < tabPositions.size) {
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[state.activeSimSlot]),
                        color = Color.Cyan
                    )
                }
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
        // Module Update Card
        if (state.moduleUpdateAvailable) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFFF9800).copy(alpha = 0.2f)),
                border = BorderStroke(1.dp, Color(0xFFFF9800))
            ) {
                Row(
                    Modifier.padding(12.dp).clickable { onNavigateToSettings() },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Info, contentDescription = null, tint = Color(0xFFFF9800))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text("MODULE UPDATE AVAILABLE", color = Color(0xFFFF9800), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        Text("New version: ${state.availableModuleVersion}", color = Color.White, fontSize = 10.sp)
                        Text("Tap to open Settings and update", color = Color.Gray, fontSize = 9.sp)
                    }
                    Icon(Icons.Default.ArrowForward, contentDescription = null, tint = Color(0xFFFF9800))
                }
            }
        }

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
            
            // SYSTEM INTEGRITY CARD
            Card(
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1F2D)),
                border = BorderStroke(1.dp, Color.Cyan.copy(alpha = 0.3f))
            ) {
                Column(Modifier.padding(12.dp)) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("SYSTEM INTEGRITY SCAN", color = Color.Cyan, fontWeight = FontWeight.Bold, fontSize = 10.sp)
                            if (state.isLoadingCve) {
                                Spacer(Modifier.width(8.dp))
                                CircularProgressIndicator(
                                    modifier = Modifier.size(12.dp),
                                    color = Color.Cyan,
                                    strokeWidth = 2.dp
                                )
                            }
                        }
                        Text("Chipset: ${state.detectedChipset} | Baseband: ${state.detectedBaseband}", color = Color.White, fontSize = 11.sp)
                        Text("Security Patch: ${state.securityPatch} | CVE Sync: ${state.lastCveUpdate}", color = Color.Gray, fontSize = 10.sp)
                        Text("CVE Database: ${state.totalCveCount} total | ${state.chipsetCveCount} for chipset", color = Color.LightGray, fontSize = 10.sp)
                        Text(
                            if (state.isLoadingCve) "Updating CVE database..." 
                            else if(state.vulnerabilities.isEmpty()) "No known firmware vulnerabilities detected." 
                            else "Security Advisory: ${state.vulnerabilities.size} issues found!", 
                            color = if (state.isLoadingCve) Color.Yellow 
                            else if(state.vulnerabilities.isEmpty()) Color.Green 
                            else Color.Yellow, 
                            fontSize = 10.sp
                        )
                    }
                    
                    Spacer(Modifier.height(12.dp))
                    
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Button(
                            onClick = { onShowCveDialog() },
                            modifier = Modifier.size(width = 80.dp, height = 32.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color.Yellow),
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                        ) {
                            Text("OPEN CVE LIST", color = Color.Black, fontSize = 8.sp, fontWeight = FontWeight.Bold)
                        }
                        IconButton(
                            onClick = { viewModel.refreshCveDatabase() },
                            modifier = Modifier.size(32.dp),
                            enabled = !state.isLoadingCve
                        ) {
                            if (state.isLoadingCve) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    color = Color(0xFFFF9800),
                                    strokeWidth = 2.dp
                                )
                            } else {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh Database", tint = Color(0xFFFF9800), modifier = Modifier.size(20.dp))
                            }
                        }
                    }
                }
            }

            SignalChart(activeSim.rssiHistory)
            Spacer(Modifier.height(16.dp))

            AnimatedVisibility(
                visible = state.activeThreats.isNotEmpty() || state.vulnerabilities.isNotEmpty(),
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column {
                    if (state.activeThreats.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF420000)),
                            border = BorderStroke(1.dp, Color.Red)
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
fun SecurityScreen(viewModel: ForensicViewModel) {
    val settings by viewModel.settings.collectAsState()
    val dashboardState by viewModel.dashboardState.collectAsState()

    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("SECURITY CONTROLS", fontWeight = FontWeight.Black, color = Color.Cyan, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            Text("Direct interaction with Radio/Baseband", color = Color.Gray, fontSize = 12.sp)
            Spacer(Modifier.height(24.dp))
        }

        if (dashboardState.hasRoot) {
            item {
                Text("SNAPDRAGON MODEM TELEMETRY", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1F2D))) {
                    Column(Modifier.padding(16.dp)) {
                        val activeSim = if(dashboardState.activeSimSlot == 0) dashboardState.sim0 else dashboardState.sim1
                        DetailRow("Cipher Algorithm", activeSim.cipherAlgo)
                        DetailRow("RRC Connection", activeSim.rrcStatus)
                        DetailRow("Modem Hardening", if(dashboardState.isHardeningModuleActive) "Active" else "Inactive (Root only)")
                    }
                }
                Spacer(Modifier.height(24.dp))

                Text("HARDENING MODULE ACTIONS", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { viewModel.resetRadio() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E1E1E)),
                        border = BorderStroke(1.dp, Color.Cyan)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, tint = Color.Cyan, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("RESET MODEM", color = Color.Cyan, fontSize = 10.sp)
                    }
                    Button(
                        onClick = { viewModel.triggerPanic() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF420000)),
                        border = BorderStroke(1.dp, Color.Red)
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = Color.Red, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("PANIC MODE", color = Color.Red, fontSize = 10.sp)
                    }
                    Button(
                        onClick = { viewModel.recoverFromPanic() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E1E1E)),
                        border = BorderStroke(1.dp, Color.Green)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, tint = Color.Green, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("RESET WLAN", color = Color.Green, fontSize = 10.sp)
                    }
                }
                Spacer(Modifier.height(24.dp))
            }
        }

        item {
            SecurityOptionCard(
                title = "Automatic Threat Mitigation",
                subtitle = "App takes immediate action (Reset/Panic) upon high-confidence threat detection.",
                checked = settings.autoMitigation,
                onCheckedChange = { viewModel.updateAutoMitigation(it) },
                icon = Icons.Default.Build,
                iconColor = Color.Cyan
            )
            Spacer(Modifier.height(16.dp))
        }

        item {
            SecurityOptionCard(
                title = "Block GSM Registrations",
                subtitle = "Forcefully prevent connection to 2G/GSM networks. (Hardware level if module active)",
                checked = settings.blockGsm,
                onCheckedChange = { viewModel.updateBlockGsm(it) },
                icon = Icons.Default.Lock,
                iconColor = Color.Red
            )
            Spacer(Modifier.height(16.dp))
        }

        item {
            SecurityOptionCard(
                title = "Reject A5/0 Cipher",
                subtitle = "Reject connections if the network requests A5/0 (No Encryption).",
                checked = settings.rejectA50,
                onCheckedChange = { viewModel.updateRejectA50(it) },
                icon = Icons.Default.Warning,
                iconColor = Color.Yellow
            )
            Spacer(Modifier.height(16.dp))
        }

        item {
            SecurityOptionCard(
                title = "Mark Fake-Cells",
                subtitle = "Visually highlight suspected IMSI Catchers and Fake Cells on the map and audit logs.",
                checked = settings.markFakeCells,
                onCheckedChange = { viewModel.updateMarkFakeCells(it) },
                icon = Icons.Default.Place,
                iconColor = Color.Cyan
            )
            Spacer(Modifier.height(16.dp))
        }

        item {
            SecurityOptionCard(
                title = "Force Immediate LTE",
                subtitle = "Emergency button to force the modem back into LTE/4G mode immediately.",
                checked = settings.forceLte,
                onCheckedChange = { viewModel.updateForceLte(it) },
                icon = Icons.Default.Refresh,
                iconColor = Color.Green
            )
            Spacer(Modifier.height(16.dp))
        }

        if (dashboardState.isHardeningModuleActive) {
            item {
                Text("ADVANCED HARDENING CONTROLS", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
            }

            item {
                SecurityOptionCard(
                    title = "Zero-Day Protection",
                    subtitle = "Dynamic vulnerability response with live CVE database sync and emergency patches.",
                    checked = settings.zeroDayProtection,
                    onCheckedChange = { viewModel.updateZeroDayProtection(it) },
                    icon = Icons.Default.Lock,
                    iconColor = Color(0xFFFF9800)
                )
                Spacer(Modifier.height(16.dp))
            }

            item {
                SecurityOptionCard(
                    title = "Geo-Fencing Protection",
                    subtitle = "Whitelist known cell IDs and block connections to unknown/fake towers.",
                    checked = settings.geoFencingProtection,
                    onCheckedChange = { viewModel.updateGeoFencingProtection(it) },
                    icon = Icons.Default.Place,
                    iconColor = Color(0xFF9C27B0)
                )
                Spacer(Modifier.height(16.dp))
            }

            item {
                SecurityOptionCard(
                    title = "Advanced Telemetry",
                    subtitle = "Extended modem logging and protocol traces for deep forensic analysis.",
                    checked = settings.advancedTelemetry,
                    onCheckedChange = { viewModel.updateAdvancedTelemetry(it) },
                    icon = Icons.Default.Info,
                    iconColor = Color(0xFF00BCD4)
                )
                Spacer(Modifier.height(16.dp))
            }

            item {
                SecurityOptionCard(
                    title = "Extended Panic Mode",
                    subtitle = "Full system lockdown with network isolation and hardware radio disable.",
                    checked = settings.extendedPanicMode,
                    onCheckedChange = { viewModel.updateExtendedPanicMode(it) },
                    icon = Icons.Default.Warning,
                    iconColor = Color(0xFFF44336)
                )
                Spacer(Modifier.height(16.dp))
            }

            item {
                SecurityOptionCard(
                    title = "Real-time Modem Monitoring",
                    subtitle = "Continuous monitoring of modem health, temperature, and RIL queue status.",
                    checked = settings.realTimeModemMonitoring,
                    onCheckedChange = { viewModel.updateRealTimeModemMonitoring(it) },
                    icon = Icons.Default.Settings,
                    iconColor = Color(0xFF4CAF50)
                )
                Spacer(Modifier.height(24.dp))
            }

            item {
                Text("ACTIONS", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { viewModel.syncCveDatabase() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E1E1E)),
                        border = BorderStroke(1.dp, Color(0xFFFF9800))
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, tint = Color(0xFFFF9800), modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("SYNC CVE", color = Color(0xFFFF9800), fontSize = 10.sp)
                    }
                    Button(
                        onClick = { viewModel.triggerForensicDump() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E1E1E)),
                        border = BorderStroke(1.dp, Color(0xFF00BCD4))
                    ) {
                        Icon(Icons.Default.Build, contentDescription = null, tint = Color(0xFF00BCD4), modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("FORENSIC", color = Color(0xFF00BCD4), fontSize = 10.sp)
                    }
                }
                Spacer(Modifier.height(24.dp))
            }
        }

        item {
            if (!dashboardState.hasRoot) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF330000)),
                    border = BorderStroke(1.dp, Color.Red)
                ) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = Color.Red)
                        Spacer(Modifier.width(12.dp))
                        Text("ROOT NOT DETECTED. Most security controls require Root access to interact with the modem driver.", color = Color.White, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

@Composable
fun SecurityOptionCard(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit, icon: ImageVector, iconColor: Color) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E)),
        border = if (checked) BorderStroke(1.dp, iconColor.copy(alpha = 0.5f)) else null
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = iconColor, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(12.dp))
                Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Spacer(Modifier.weight(1f))
                Switch(
                    checked = checked,
                    onCheckedChange = onCheckedChange,
                    colors = SwitchDefaults.colors(checkedThumbColor = iconColor, checkedTrackColor = iconColor.copy(alpha = 0.5f))
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(subtitle, color = Color.Gray, fontSize = 12.sp, lineHeight = 18.sp)
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
fun SignalChart(history: List<Int>) {
    Card(
        modifier = Modifier.fillMaxWidth().height(100.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF121212)),
        border = BorderStroke(1.dp, Color.DarkGray)
    ) {
        Column(Modifier.padding(8.dp)) {
            Text("SIGNAL STABILITY (LIVE)", color = Color.Gray, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            ComposeCanvas(modifier = Modifier.fillMaxSize()) {
                if (history.isEmpty()) return@ComposeCanvas

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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: ForensicViewModel) {
    val settings by viewModel.settings.collectAsState()
    val dashboardState by viewModel.dashboardState.collectAsState()
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val btcAddress = "1Q1Vmcb1FggH6SGmDoDBjYRqMJdbhratYZ"

    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("SYSTEM STATUS", fontWeight = FontWeight.Black, color = Color.Cyan, fontSize = 18.sp)
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusIndicator("ROOT", dashboardState.hasRoot, Modifier.weight(1f))
                StatusIndicator("XPOSED", dashboardState.isXposedActive, Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            StatusIndicator("HARDENING MODULE", dashboardState.isHardeningModuleActive, Modifier.fillMaxWidth())
            Spacer(Modifier.height(24.dp))
        }

        item {
            Text("MAGISK / KERNELSU HARDENING", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text(
                        "The Sentry Hardening Module provides deep system integration to enforce radio security and prevent IMSI Catcher attacks on the baseband level.",
                        color = Color.Gray,
                        fontSize = 12.sp
                    )
                    Spacer(Modifier.height(16.dp))

                    if (dashboardState.isHardeningModuleActive) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Check, contentDescription = null, tint = Color.Green)
                            Spacer(Modifier.width(8.dp))
                            Column {
                                Text("Module installed and active", color = Color.Green, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                Text("Version: ${dashboardState.currentModuleVersion}", color = Color.Gray, fontSize = 11.sp)
                            }
                        }
                        
                        // Show update notification if available
                        if (dashboardState.moduleUpdateAvailable) {
                            Spacer(Modifier.height(12.dp))
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = Color(0xFFFF9800).copy(alpha = 0.2f)),
                                border = BorderStroke(1.dp, Color(0xFFFF9800))
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.Info, contentDescription = null, tint = Color(0xFFFF9800), modifier = Modifier.size(16.dp))
                                        Spacer(Modifier.width(8.dp))
                                        Text("UPDATE AVAILABLE", color = Color(0xFFFF9800), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                    }
                                    Spacer(Modifier.height(4.dp))
                                    Text("New version: ${dashboardState.availableModuleVersion}", color = Color.White, fontSize = 11.sp)
                                }
                            }
                        }
                        
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = { viewModel.installHardeningModule(context) },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (dashboardState.moduleUpdateAvailable) Color(0xFFFF9800) else Color.Gray,
                                contentColor = Color.White
                            )
                        ) {
                            Icon(Icons.Default.Refresh, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text(if (dashboardState.moduleUpdateAvailable) "UPDATE MODULE" else "REINSTALL MODULE", fontWeight = FontWeight.Bold)
                        }
                    } else if (dashboardState.hasRoot) {
                        Button(
                            onClick = { viewModel.installHardeningModule(context) },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color.Cyan, contentColor = Color.Black)
                        ) {
                            Icon(Icons.Default.Build, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("INSTALL HARDENING MODULE", fontWeight = FontWeight.Bold)
                        }
                        Text(
                            "Note: A reboot is required after installation.",
                            color = Color.Yellow.copy(alpha = 0.7f),
                            fontSize = 10.sp,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                    } else {
                        Text(
                            "Root access required to install the Hardening Module.",
                            color = Color.Red.copy(alpha = 0.7f),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }

        item {
            Text("API CONFIGURATION", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(16.dp))

            // BEACON DB
            SettingsRow("BeaconDB (No Key)", "Public crowdsourced database", settings.useBeaconDb) {
                viewModel.updateUseBeaconDb(it)
            }
            
            Spacer(Modifier.height(16.dp))
            
            // OPEN CELL ID
            SettingsRow("OpenCellID API (Free)", "Required for Area Scans", settings.useOpenCellId) {
                viewModel.updateUseOpenCellId(it)
            }
            if (settings.useOpenCellId) {
                TextField(
                    value = settings.openCellIdKey,
                    onValueChange = { viewModel.updateOpenCellIdKey(it) },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    label = { Text("OpenCellID API Key") },
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Color(0xFF1E1E1E),
                        unfocusedContainerColor = Color(0xFF121212),
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.Gray
                    ),
                    singleLine = true
                )
            }

            Spacer(Modifier.height(16.dp))
            Text("Using OpenCellID allows the app to populate the map with known towers in your current area.", color = Color.Gray, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
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
                    text = "Developer: fzer0x | Version: 0.4.2",
                    color = Color.Gray,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )

                Spacer(Modifier.height(12.dp))

                Surface(
                    onClick = {
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("bitcoin:$btcAddress"))
                            context.startActivity(intent)
                        } catch (e: Exception) {
                            clipboardManager.setText(AnnotatedString(btcAddress))
                            Toast.makeText(context, "BTC Address copied to clipboard", Toast.LENGTH_SHORT).show()
                        }
                    },
                    color = Color(0xFFF7931A).copy(alpha = 0.1f),
                    shape = RoundedCornerShape(20.dp),
                    border = BorderStroke(1.dp, Color(0xFFF7931A).copy(alpha = 0.5f))
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Share, // Bitcoin icon placeholder
                            contentDescription = "Bitcoin",
                            tint = Color(0xFFF7931A),
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "Buy Me a Beer (Bitcoin)",
                            color = Color.White,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

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
fun RebootDialog(onDismiss: () -> Unit, onReboot: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "Reboot Required",
                color = Color.Cyan,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column {
                Text(
                    "The Sentry Radio Hardening Module has been successfully installed/updated.",
                    color = Color.White,
                    fontSize = 14.sp
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "A system reboot is required to activate the module and apply all security enhancements.",
                    color = Color.Gray,
                    fontSize = 12.sp
                )
                Spacer(Modifier.height(12.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFF9800).copy(alpha = 0.1f)),
                    border = BorderStroke(1.dp, Color(0xFFFF9800))
                ) {
                    Row(
                        Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = null,
                            tint = Color(0xFFFF9800),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "Please reboot your device to apply the changes.",
                            color = Color(0xFFFF9800),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onReboot,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Cyan,
                    contentColor = Color.Black
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    Icons.Default.Refresh,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "REBOOT NOW",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = onDismiss,
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.Gray
                ),
                border = BorderStroke(1.dp, Color.Gray),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "LATER",
                    fontSize = 14.sp
                )
            }
        },
        containerColor = Color(0xFF1E1E1E),
        textContentColor = Color.White
    )
}

@Composable
fun MapForensicScreen(viewModel: ForensicViewModel) {
    val context = LocalContext.current
    val towers by viewModel.allTowers.collectAsState()
    val lifecycleOwner = LocalLifecycleOwner.current
    val settings by viewModel.settings.collectAsState()

    val mapView = remember {
        MapView(context).apply {
            setTileSource(TileSourceFactory.MAPNIK)
            setMultiTouchControls(true)
            isTilesScaledToDpi = true
            controller.setZoom(15.0)
        }
    }

    val locationProvider = remember { GpsMyLocationProvider(context) }
    val locationOverlay = remember {
        object : MyLocationNewOverlay(locationProvider, mapView) {
            override fun onSingleTapConfirmed(e: android.view.MotionEvent, mapView: MapView): Boolean {
                viewModellessMarkerClose(mapView)
                return false 
            }
        }.apply {
            enableMyLocation()
        }
    }

    // Restore last state or center on current location
    LaunchedEffect(mapView) {
        val lastState = viewModel.getLastMapState()
        if (lastState != null) {
            mapView.controller.setCenter(GeoPoint(lastState.first, lastState.second))
            mapView.controller.setZoom(lastState.third)
        } else {
            val currentLoc = viewModel.getFreshLocation()
            if (currentLoc != null) {
                mapView.controller.setCenter(GeoPoint(currentLoc.latitude, currentLoc.longitude))
                mapView.controller.setZoom(15.0)
            }
        }
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> {
                    mapView.onResume()
                    locationOverlay.enableMyLocation()
                }
                Lifecycle.Event.ON_PAUSE -> {
                    // Save state
                    val center = mapView.mapCenter
                    viewModel.saveMapState(center.latitude, center.longitude, mapView.zoomLevelDouble)
                    mapView.onPause()
                    locationOverlay.disableMyLocation()
                }
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
            factory = {
                if (mapView.overlays.none { it is MyLocationNewOverlay }) {
                    mapView.overlays.add(locationOverlay)
                }
                // Add events overlay to handle map clicks and prevent empty bubbles
                val mapEventsOverlay = MapEventsOverlay(object : MapEventsReceiver {
                    override fun singleTapConfirmedHelper(p: GeoPoint?): Boolean {
                        // Close all open info windows when tapping on empty map
                        viewModellessMarkerClose(mapView)
                        return true
                    }
                    override fun longPressHelper(p: GeoPoint?): Boolean = false
                })
                mapView.overlays.add(0, mapEventsOverlay)
                mapView
            },
            modifier = Modifier.fillMaxSize(),
            update = { view ->
                // Remove markers/polygons but keep location and events overlay
                view.overlays.removeAll { it is Marker || it is Polyline || it is Polygon }
                
                towers.filter { it.latitude != null && it.longitude != null }
                    .forEach { tower ->
                        val point = GeoPoint(tower.latitude!!, tower.longitude!!)

                        val ratColor = when {
                            tower.rat.contains("LTE", true) -> android.graphics.Color.BLUE
                            tower.rat.contains("NR", true) || tower.rat.contains("5G", true) -> android.graphics.Color.MAGENTA
                            tower.rat.contains("UMTS", true) || tower.rat.contains("WCDMA", true) -> android.graphics.Color.GREEN
                            else -> android.graphics.Color.YELLOW
                        }

                        tower.range?.let { r ->
                            val circle = Polygon(view)
                            circle.points = Polygon.pointsAsCircle(point, r)
                            val alpha = if (tower.isMissingInDb) 100 else 40
                            circle.fillPaint.color = Color(ratColor).copy(alpha = alpha / 255f).toArgb()
                            circle.outlinePaint.color = ratColor
                            circle.outlinePaint.strokeWidth = if(tower.isMissingInDb) 5f else 2f
                            circle.infoWindow = null 
                            // Consuming the click without bubble
                            circle.setOnClickListener { _, _, _ -> 
                                viewModellessMarkerClose(view)
                                true 
                            } 
                            view.overlays.add(circle)
                        }

                        val marker = Marker(view)
                        marker.position = point
                        marker.title = "Cell ID: ${tower.cellId}"
                        marker.snippet = """
                            RAT: ${tower.rat}
                            MCC/MNC: ${tower.mcc}/${tower.mnc}
                            LAC/TAC: ${tower.lac}
                            PCI: ${tower.pci ?: "N/A"}
                            TA: ${tower.ta ?: "N/A"}
                            Signal: ${tower.dbm ?: "N/A"} dBm
                            Verification: ${if(tower.isVerified) "Verified (${tower.source})" else "Local GPS"}
                        """.trimIndent()

                        marker.icon = createTowerIcon(context, ratColor, tower.isMissingInDb)
                        marker.setAnchor(Marker.ANCHOR_CENTER, Marker.ANCHOR_BOTTOM)
                        view.overlays.add(marker)
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
                },
                containerColor = Color.Yellow,
                contentColor = Color.Black
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Sync API")
            }

            FloatingActionButton(
                onClick = {
                    val location = locationOverlay.myLocation
                    if (location != null) {
                        mapView.controller.animateTo(location)
                        mapView.controller.setZoom(18.0)
                    } else {
                        // FORCE LOCATION UPDATE
                        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
                        val listener = object : android.location.LocationListener {
                            override fun onLocationChanged(loc: Location) {
                                mapView.controller.animateTo(GeoPoint(loc.latitude, loc.longitude))
                                mapView.controller.setZoom(18.0)
                                lm.removeUpdates(this)
                            }
                            override fun onStatusChanged(p: String?, s: Int, e: Bundle?) {}
                            override fun onProviderEnabled(p: String) {}
                            override fun onProviderDisabled(p: String) {}
                        }
                        
                        try {
                            val providers = lm.getProviders(true)
                            for (provider in providers) {
                                lm.requestLocationUpdates(provider, 0L, 0f, listener)
                            }
                            
                            val lastLoc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER) 
                                       ?: lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
                            if (lastLoc != null) {
                                mapView.controller.animateTo(GeoPoint(lastLoc.latitude, lastLoc.longitude))
                                mapView.controller.setZoom(18.0)
                            } else {
                                Toast.makeText(context, "Locating... Please wait for GPS.", Toast.LENGTH_LONG).show()
                            }
                        } catch (e: SecurityException) {
                            Toast.makeText(context, "Permission Error", Toast.LENGTH_SHORT).show()
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

private fun viewModellessMarkerClose(mapView: MapView) {
    mapView.overlays.forEach {
        if (it is OverlayWithIW) {
            it.closeInfoWindow()
        }
    }
}

private fun createTowerIcon(context: android.content.Context, color: Int, isWarning: Boolean): Drawable {
    val size = 40
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bitmap)
    val paint = Paint()
    
    // Shadow
    paint.color = android.graphics.Color.BLACK
    paint.alpha = 100
    canvas.drawCircle(size / 2f + 2, size / 2f + 2, size / 3f, paint)
    
    // Main Circle
    paint.alpha = 255
    paint.color = color
    canvas.drawCircle(size / 2f, size / 2f, size / 3f, paint)
    
    // Warning dot
    if (isWarning) {
        paint.color = android.graphics.Color.RED
        canvas.drawCircle(size / 2f, size / 2f, size / 6f, paint)
    }
    
    return BitmapDrawable(context.resources, bitmap)
}

private fun Color.toArgb(): Int = (alpha * 255.0f + 0.5f).toInt() shl 24 or
        ((red * 255.0f + 0.5f).toInt() shl 16) or
        ((green * 255.0f + 0.5f).toInt() shl 8) or
        (blue * 255.0f + 0.5f).toInt()

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
fun AdvancedAnalyticsScreen(viewModel: ForensicViewModel) {
    val state by viewModel.dashboardState.collectAsState()
    val logs by viewModel.allLogs.collectAsState()
    val blockingEvents by viewModel.blockingEvents.collectAsState()
    val scrollState = rememberScrollState()

    Column(Modifier.fillMaxSize().verticalScroll(scrollState)) {
        TabRow(
            selectedTabIndex = state.activeSimSlot,
            containerColor = Color(0xFF121212),
            contentColor = Color.Cyan,
            divider = {},
            indicator = { tabPositions ->
                if (state.activeSimSlot < tabPositions.size) {
                    TabRowDefaults.SecondaryIndicator(
                        Modifier.tabIndicatorOffset(tabPositions[state.activeSimSlot]),
                        color = Color.Cyan
                    )
                }
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

            val simBlockingEvents = blockingEvents.filter { it.simSlot == state.activeSimSlot }
            if (simBlockingEvents.isNotEmpty()) {
                Text("ACTIVE PROTECTIONS", color = Color(0xFF00E676), fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
                BlockingSuccessCard(simBlockingEvents)
                Spacer(Modifier.height(24.dp))
            }

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
fun BlockingSuccessCard(blockingEvents: List<dev.fzer0x.imsicatcherdetector2.service.BlockingEvent>) {
    val gsmBlocks = blockingEvents.filter { it.blockType == "GSM_DOWNGRADE" }
    val a50Blocks = blockingEvents.filter { it.blockType == "A5_0_CIPHER" }
    val silentSmsBlocks = blockingEvents.filter { it.blockType == "SILENT_SMS" }
    val successColor = Color(0xFF00E676)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D3D0D)),
        border = BorderStroke(1.dp, successColor.copy(alpha = 0.5f))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Check, contentDescription = null, tint = successColor, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(8.dp))
                Text("THREATS SUCCESSFULLY BLOCKED", color = successColor, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }

            Spacer(Modifier.height(16.dp))

            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (gsmBlocks.isNotEmpty()) {
                    AnalyticsMetric("GSM Downgrade", gsmBlocks.size.toString(), successColor, Modifier.weight(1f))
                }
                if (a50Blocks.isNotEmpty()) {
                    AnalyticsMetric("A5/0 Cipher", a50Blocks.size.toString(), successColor, Modifier.weight(1f))
                }
                if (silentSmsBlocks.isNotEmpty()) {
                    AnalyticsMetric("Silent SMS", silentSmsBlocks.size.toString(), successColor, Modifier.weight(1f))
                }
            }

            Spacer(Modifier.height(12.dp))
            Text("Recent Blocks:", color = successColor, fontSize = 11.sp, fontWeight = FontWeight.Bold)

            blockingEvents.sortedByDescending { it.timestamp }.take(3).forEach { event ->
                Spacer(Modifier.height(4.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Check, contentDescription = null, tint = successColor, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            when(event.blockType) {
                                "GSM_DOWNGRADE" -> "GSM Downgrade Blocked"
                                "A5_0_CIPHER" -> "A5/0 Encryption Blocked"
                                "SILENT_SMS" -> "Silent SMS Blocked"
                                else -> event.blockType
                            },
                            color = successColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            event.description,
                            color = successColor.copy(alpha = 0.8f),
                            fontSize = 9.sp
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(
                        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(java.util.Date(event.timestamp)),
                        color = Color.Gray,
                        fontSize = 9.sp
                    )
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
    val towers by viewModel.allTowers.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val dateFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    LazyColumn(Modifier.fillMaxSize().padding(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(logs) { log ->
            val isCritical = log.severity >= 8
            val isBlocked = log.cellId != null && blockedIds.contains(log.cellId)
            val tower = log.cellId?.let { cellId -> towers.find { it.cellId == cellId } }
            val isFakeCell = tower != null && tower.isMissingInDb && settings.markFakeCells

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onEventClick(log) },
                colors = CardDefaults.cardColors(
                    containerColor = when {
                        isBlocked -> Color(0xFF121212)
                        isFakeCell -> Color(0xFF330011)
                        isCritical -> Color(0xFF330000)
                        else -> Color(0xFF1E1E1E)
                    }
                ),
                border = when {
                    isBlocked -> BorderStroke(1.dp, Color.Gray)
                    isFakeCell -> BorderStroke(2.dp, Color(0xFFFF1493))
                    isCritical -> BorderStroke(2.dp, Color.Red)
                    else -> null
                }
            ) {
                ListItem(
                    headlineContent = {
                        val markerPrefix = when {
                            isBlocked -> " (BLOCKED)"
                            isFakeCell -> " ⚠ SUSPECTED IMSI CATCHER"
                            else -> ""
                        }
                        Text(log.description + markerPrefix,
                            color = when {
                                isBlocked -> Color.Gray
                                isFakeCell -> Color(0xFFFF1493)
                                isCritical -> Color.Red
                                else -> Color.White
                            },
                            fontWeight = if(isCritical || isFakeCell) FontWeight.Bold else FontWeight.Normal
                        )
                    },
                    supportingContent = { Text("SIM ${log.simSlot + 1} • ${log.type} • ${dateFormat.format(Date(log.timestamp))}", color = Color.Gray) },
                    trailingContent = {
                        Icon(
                            imageVector = when {
                                isBlocked -> Icons.Default.Lock
                                isFakeCell -> Icons.Default.Warning
                                else -> Icons.Default.Info
                            },
                            contentDescription = null,
                            tint = when {
                                isBlocked -> Color.Gray
                                isFakeCell -> Color(0xFFFF1493)
                                isCritical -> Color.Red
                                else -> Color.Gray
                            }
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
