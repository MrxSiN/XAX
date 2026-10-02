package com.example.target;

/** Stand-in for the controlled target app's class: the hooked method returns its argument. */
public final class XaxActivity {
    public String hookTarget(String value) {
        return value;
    }

    public String hookTarget() {
        return "OriginalResult";
    }
}
