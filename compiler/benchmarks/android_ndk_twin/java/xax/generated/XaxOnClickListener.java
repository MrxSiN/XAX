package xax.generated;

import android.view.View;
import android.widget.TextView;

/** Conventional twin of the XAX-emitted click listener (size baseline only). */
public final class XaxOnClickListener implements View.OnClickListener {
    private native void xaxOnClick(View view);

    @Override
    public void onClick(View view) {
        ((TextView) view).setText("Clicked");
        xaxOnClick(view);
    }
}
