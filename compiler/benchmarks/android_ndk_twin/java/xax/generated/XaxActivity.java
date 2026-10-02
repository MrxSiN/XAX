package xax.generated;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;

/** Conventional twin of the XAX-emitted Activity (size baseline only). */
public final class XaxActivity extends Activity {
    static {
        System.loadLibrary("xaxapp");
    }

    private native void xaxOnCreate(Bundle state);

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Button button = new Button(this);
        button.setText("XAX");
        button.setOnClickListener(new XaxOnClickListener());
        setContentView(button);
        xaxOnCreate(state);
    }
}
