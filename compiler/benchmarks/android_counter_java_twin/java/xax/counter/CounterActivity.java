package xax.counter;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;

/** Pure Java twin of the XAX counter Activity (ADR-111): same classes, state file, and behavior, no native code. */
public final class CounterActivity extends Activity {
    /** Reads the 8-byte little-endian count; optionally increments, writes, and fdatasyncs it. */
    static long counter(File filesDir, boolean increment) {
        try (FileChannel channel = FileChannel.open(new File(filesDir, "xax.counter").toPath(),
                StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE)) {
            ByteBuffer cell = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
            channel.read(cell, 0);
            long count = cell.getLong(0);
            if (increment) {
                cell.clear();
                cell.putLong(0, ++count);
                channel.write(cell, 0);
                channel.force(false);
            }
            return count;
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        }
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Button button = new Button(this);
        button.setText(Long.toString(counter(getFilesDir(), false)));
        button.setOnClickListener(new CounterClickListener());
        setContentView(button);
    }
}
