package xax.counter;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;

/** Null arm of the counter cold start (ADR-430): the twins' shell showing a fixed count, with no state file and no listener. */
public final class CounterActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Button button = new Button(this);
        button.setText("0");
        setContentView(button);
    }
}
