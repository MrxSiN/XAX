# START=1 all.sh <store> <out store>: each site function in ordered.txt (callers first), one native batch each; xaxc verify at the end
set -eu
X=/home/user/XAX/compiler/bootstrap/seed/xaxc-linux-x86_64; cur=$1; k=$((START - 1))
tail -n +$((START)) "$(dirname "$0")/ordered.txt | while read cid vals init; do
  k=$((k + 1)); cur=$(ls -t S*.xax 2>/dev/null | head -1); [ -n "$cur" ] || cur=$1; : > e; $X edit $cur e cur.list
  if ! grep -q " $cid" cur.list; then echo "skip $cid (not in store)"; continue; fi
  LIST=cur.list sh "$(dirname "$0")/mkcap.sh" $cur $cid $vals ${init:--} b$k.batch
  $X edit $cur b$k.batch S$k.xax; cur=S$k.xax; echo "step $k $cid done"
done
cur=$(ls -t S*.xax | head -1); cp $cur $2; $X verify $2 v.final && echo VERIFIED
