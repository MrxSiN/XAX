package xax.counter;

import android.app.Activity;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.widget.Button;
import java.io.File;
import java.io.FileNotFoundException;

/** Conventional Java + NDK twin of the XAX counter Activity (ADR-111, ADR-153): same classes, state file, and behavior. */
public final class CounterActivity extends Activity {
    static {
        System.loadLibrary("xaxcounter");
    }

    private native long xaxOnCreate(Bundle state, int fd);

    /** Opens the state file and detaches the descriptor; native code owns and closes it. */
    static int openState(File filesDir) {
        try {
            return ParcelFileDescriptor.open(new File(filesDir, "xax.counter"),
                    ParcelFileDescriptor.MODE_READ_WRITE | ParcelFileDescriptor.MODE_CREATE).detachFd();
        } catch (FileNotFoundException error) {
            throw new RuntimeException(error);
        }
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Button button = new Button(this);
        button.setText(Long.toString(xaxOnCreate(state, openState(getFilesDir()))));
        button.setOnClickListener(new CounterClickListener());
        setContentView(button);
    }
}
