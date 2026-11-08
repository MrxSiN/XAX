# Prototype (not applied): the AArch64 fold loop (-v LOOP=<file>) between value_facts' success (B173) and B174.
/^B[0-9]+\(/ { cur = substr($0, 2, index($0, "(") - 2) + 0 }
cur == 173 && /^br B174\(/ { sub(/^br B174\(/, "br B9200000("); print; next }
/^B174\(/ { while ((getline l < LOOP) > 0) print l; print; next }
{ print }
