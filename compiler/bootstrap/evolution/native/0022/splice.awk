# Ledger 0022: splice the expanded fold loop (-v FOLD=<file>) in front of `basics`' B78 (the first block after the
# per-function table clears).  The only edge into B78 (from B76's loop test) goes to FB0 instead; FX goes on to B78.
/^cbr / && / B78\(/ && !done { sub(/ B78\(/, " B9000000("); print; done = 1; next }
/^B78\(/ { while ((getline l < FOLD) > 0) print l; print; next }
{ print }
