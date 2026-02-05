package dev.fzer0x.imsicatcherdetector2.service

import android.content.Context
import dev.fzer0x.imsicatcherdetector2.data.ForensicEvent
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object PcapHelper {

    fun appendEventToAutoPcap(context: Context, event: ForensicEvent) {
        val file = File(context.getExternalFilesDir(null), "SentryRadio_GSMTAP.pcap")
        val isNewFile = !file.exists()

        try {
            FileOutputStream(file, true).use { fos ->
                if (isNewFile) {
                    val header = ByteBuffer.allocate(24).apply {
                        order(ByteOrder.LITTLE_ENDIAN)
                        putInt(0xa1b2c3d4.toInt()) 
                        putShort(2) 
                        putShort(4) 
                        putInt(0) 
                        putInt(0) 
                        putInt(65535) 
                        putInt(147) 
                    }
                    fos.write(header.array())
                }

                val gsmtap = ByteBuffer.allocate(16).apply {
                    put(2) 
                    put(16) 
                    put(0x01) 
                    put(0) 
                    putShort(0) 
                    put(event.signalStrength?.toByte() ?: 0) 
                    put(0) 
                    putInt(0) 
                    put(1) 
                    put(0) 
                    putShort(0) 
                }

                val payload = "[${event.type}] CID:${event.cellId} ${event.description}".toByteArray()
                val totalSize = gsmtap.capacity() + payload.size

                val pcapPacketHeader = ByteBuffer.allocate(16).apply {
                    order(ByteOrder.LITTLE_ENDIAN)
                    putInt((event.timestamp / 1000).toInt()) 
                    putInt(((event.timestamp % 1000) * 1000).toInt()) 
                    putInt(totalSize) 
                    putInt(totalSize)
                }

                fos.write(pcapPacketHeader.array())
                fos.write(gsmtap.array())
                fos.write(payload)
            }
        } catch (e: Exception) {}
    }
}
