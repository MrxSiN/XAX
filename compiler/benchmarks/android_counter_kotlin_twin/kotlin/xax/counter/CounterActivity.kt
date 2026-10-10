package xax.counter

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption

/** Pure Kotlin twin of the XAX counter Activity (ADR-111): same classes, state file, and behavior, no native code. */
class CounterActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val button = Button(this)
        button.text = counter(filesDir, false).toString()
        button.setOnClickListener(CounterClickListener())
        setContentView(button)
    }

    companion object {
        /** Reads the 8-byte little-endian count; optionally increments, writes, and fdatasyncs it. */
        @JvmStatic
        fun counter(filesDir: File, increment: Boolean): Long =
            FileChannel.open(File(filesDir, "xax.counter").toPath(),
                StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE).use { channel ->
                val cell = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
                channel.read(cell, 0)
                var count = cell.getLong(0)
                if (increment) {
                    cell.clear()
                    cell.putLong(0, ++count)
                    channel.write(cell, 0)
                    channel.force(false)
                }
                count
            }
    }
}
