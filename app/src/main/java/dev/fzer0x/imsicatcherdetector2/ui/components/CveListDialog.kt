package dev.fzer0x.imsicatcherdetector2.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import dev.fzer0x.imsicatcherdetector2.security.CveEntry
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CveListDialog(
    vulnerabilities: List<CveEntry>,
    chipset: String,
    baseband: String,
    securityPatch: String,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.8f),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E)),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "CVE VULNERABILITY REPORT",
                            color = Color.Cyan,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Black
                        )
                        Text(
                            text = "Device: $chipset | $baseband",
                            color = Color.Gray,
                            fontSize = 12.sp
                        )
                        Text(
                            text = "Security Patch: $securityPatch",
                            color = Color.Gray,
                            fontSize = 12.sp
                        )
                    }
                    Button(
                        onClick = onDismiss,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF333333)),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Text("CLOSE", color = Color.White, fontSize = 12.sp)
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Summary
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1F2D))
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(
                                text = "${vulnerabilities.size} CVEs Found",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                            Text(
                                text = "Click items for details",
                                color = Color.Gray,
                                fontSize = 11.sp
                            )
                        }
                        val criticalCount = vulnerabilities.count { it.severity >= 9.0 }
                        val highCount = vulnerabilities.count { it.severity >= 7.0 && it.severity < 9.0 }
                        Row {
                            if (criticalCount > 0) {
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = Color(0xFF420000)),
                                    modifier = Modifier.padding(end = 8.dp)
                                ) {
                                    Text(
                                        text = "CRITICAL: $criticalCount",
                                        color = Color.Red,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                    )
                                }
                            }
                            if (highCount > 0) {
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = Color(0xFF332200))
                                ) {
                                    Text(
                                        text = "HIGH: $highCount",
                                        color = Color.Yellow,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                    )
                                }
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // CVE List
                if (vulnerabilities.isEmpty()) {
                    Box(
                        modifier = Modifier.fillMaxWidth().weight(1f),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = "✓ NO VULNERABILITIES DETECTED",
                                color = Color.Green,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "Your device appears secure",
                                color = Color.Gray,
                                fontSize = 12.sp
                            )
                        }
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(vulnerabilities) { cve ->
                            CveItem(cve = cve)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CveItem(cve: CveEntry) {
    val dateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
    val publishedDate = dateFormat.format(Date(cve.publishedDate))
    
    val severityColor = when {
        cve.severity >= 9.0 -> Color(0xFF420000)
        cve.severity >= 7.0 -> Color(0xFF332200)
        cve.severity >= 4.0 -> Color(0xFF334422)
        else -> Color(0xFF222233)
    }
    
    val severityTextColor = when {
        cve.severity >= 9.0 -> Color.Red
        cve.severity >= 7.0 -> Color.Yellow
        cve.severity >= 4.0 -> Color(0xFF88BB88)
        else -> Color.Gray
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = severityColor),
        border = BorderStroke(1.dp, severityTextColor.copy(alpha = 0.3f))
    ) {
        Column(
            modifier = Modifier.padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = cve.cveId,
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = cve.description,
                        color = Color.LightGray,
                        fontSize = 11.sp,
                        lineHeight = 14.sp
                    )
                }
                Card(
                    colors = CardDefaults.cardColors(containerColor = severityTextColor.copy(alpha = 0.2f))
                ) {
                    Text(
                        text = "${cve.severity}/10",
                        color = severityTextColor,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Published: $publishedDate",
                    color = Color.Gray,
                    fontSize = 10.sp
                )
                if (cve.isRelevantForImsiCatcher) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF442266))
                    ) {
                        Text(
                            text = "IMSI-CATCHER RELEVANT",
                            color = Color(0xFFBB66DD),
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
            }
        }
    }
}
