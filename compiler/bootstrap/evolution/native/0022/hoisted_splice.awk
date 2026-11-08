# Ledger 0022: the hoisted-register loop (-v LOOP=<file>) between the emit function's dry run (B26) and the frame (B27).
/^br B27\(/ && cur == 26 { sub(/^br B27\(/, "br B9100000("); print; next }
/^B27\(/ { while ((getline l < LOOP) > 0) print l; print; next }
/^B[0-9]+\(/ { cur = substr($0, 2, index($0, "(") - 2) + 0 }
{ print }
