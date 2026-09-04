# Runs INSIDE a wormhole_dvm disposable. Dumps the PGP even/odd wordlist from the
# installed magic-wormhole package so the client can mint codes without needing
# wormhole itself. Run via:
#   tools/dvm-run --target @dispvm:wormhole_dvm --label "extract wordlist" \
#       -f tools/extract-wordlist.sh > share/wordlist.txt
PY=~/.local/share/pipx/venvs/magic-wormhole/bin/python
exec $PY - <<'PYEOF'
import wormhole._wordlist as W

rw = W.raw_words
assert len(rw) == 256, "expected 256 byte entries, got %d" % len(rw)

evens, odds = [], []
for k in sorted(rw, key=lambda x: int(x, 16)):
    e, o = rw[k]
    evens.append(e)
    odds.append(o)

assert len(set(evens)) == 256 and len(set(odds)) == 256, "words not distinct"

print("# magic-wormhole PGP wordlist, extracted verbatim from the installed")
print("# package (wormhole._wordlist.raw_words), in canonical byte order.")
print("# Regenerate with tools/extract-wordlist.sh. Do not hand-edit.")
print("# even words are used at even positions, odd at odd positions.")
print("[even]")
for w in evens:
    print(w)
print("[odd]")
for w in odds:
    print(w)
PYEOF
