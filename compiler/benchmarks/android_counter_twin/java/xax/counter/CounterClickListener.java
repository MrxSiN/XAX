package xax.counter;

import android.view.View;
import android.widget.TextView;

/** Conventional twin of the XAX counter click listener. */
public final class CounterClickListener implements View.OnClickListener {
    private native long xaxOnClick(View view, int fd);

    @Override
    public void onClick(View view) {
        int fd = CounterActivity.openState(view.getContext().getFilesDir());
        ((TextView) view).setText(Long.toString(xaxOnClick(view, fd)));
    }
}
