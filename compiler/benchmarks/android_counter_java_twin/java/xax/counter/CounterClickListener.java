package xax.counter;

import android.view.View;
import android.widget.TextView;

/** Pure Java twin of the XAX counter click listener. */
public final class CounterClickListener implements View.OnClickListener {
    @Override
    public void onClick(View view) {
        ((TextView) view).setText(Long.toString(CounterActivity.counter(view.getContext().getFilesDir(), true)));
    }
}
