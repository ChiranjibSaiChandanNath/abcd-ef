#!/bin/bash
FILE="$1"

echo "=============================="
echo "   MALWARE SANDBOX ANALYSIS"
echo "=============================="

echo ""
echo "=== [1] FILE INFORMATION ==="
file "$FILE" 2>&1

echo ""
echo "=== [2] FILE SIZE ==="
wc -c < "$FILE" 2>&1

echo ""
echo "=== [3] ENTROPY CHECK ==="
# High entropy = packed/encrypted = suspicious
ent_check=$(cat "$FILE" | tr -d '\0' | wc -c)
echo "Readable bytes: $ent_check"

echo ""
echo "=== [4] SUSPICIOUS STRINGS ==="
strings "$FILE" 2>&1 | grep -iE \
"(http|https|ftp|cmd|exec|shell|payload|download|upload|\
password|passwd|keylog|encrypt|decrypt|ransom|bitcoin|\
192\.168|10\.0|socket|connect|bind|listen|backdoor|\
/etc/passwd|/etc/shadow|chmod|sudo|wget|curl|nc |ncat)" \
| head -50

echo ""
echo "=== [5] ALL READABLE STRINGS ==="
strings "$FILE" 2>&1 | head -100

echo ""
echo "=== [6] HEX HEADER (first 32 bytes) ==="
xxd "$FILE" 2>&1 | head -4

echo ""
echo "=== [7] DYNAMIC EXECUTION ==="
EXT="${FILE##*.}"
case "$EXT" in
    py)
        echo "[Running Python file with timeout]"
        timeout 5 strace -e trace=file,network,process \
            python3 "$FILE" 2>&1 | head -80
        ;;
    sh|bash)
        echo "[Running shell script with timeout]"
        timeout 5 strace -e trace=file,network,process \
            bash "$FILE" 2>&1 | head -80
        ;;
    js)
        echo "[Running JavaScript with timeout]"
        timeout 5 strace -e trace=file,network,process \
            node "$FILE" 2>&1 | head -80
        ;;
    elf|*)
        echo "[Attempting native execution with strace]"
        timeout 5 strace -e trace=file,network,process \
            "$FILE" 2>&1 | head -80 \
        || echo "[INFO] Not a native Linux executable or permission denied"
        ;;
esac

echo ""
echo "=== [8] LIBRARY CALLS (ltrace) ==="
timeout 3 ltrace "$FILE" 2>&1 | head -30 \
    || echo "[INFO] ltrace not applicable for this file type"

echo ""
echo "=============================="
echo "         SCAN COMPLETE"
echo "=============================="
