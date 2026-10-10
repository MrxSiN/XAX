package xax.counter

import android.view.View
import android.widget.TextView

/** Pure Kotlin twin of the XAX counter click listener. */
class CounterClickListener : View.OnClickListener {
    override fun onClick(view: View) {
        (view as TextView).text = CounterActivity.counter(view.context.filesDir, true).toString()
    }
}
