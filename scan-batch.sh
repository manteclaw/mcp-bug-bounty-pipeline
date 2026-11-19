#!/usr/bin/env bash
# MCP Bug Bounty Batch Scanner
# Scans a list of MCP server directories/repos and outputs filtered findings

set -euo pipefail

# Config
VENV="$HOME/bounty/venv"
OUTDIR="$HOME/bounty/scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MIN_SEVERITY="${MIN_SEVERITY:-HIGH}"  # HIGH or CRITICAL

# Ensure venv + output dir
source "$VENV/bin/activate"
mkdir -p "$OUTDIR"

# Targets file: one path per line
TARGETS_FILE="${1:-$HOME/bounty/targets.txt}"

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "[!] Targets file not found: $TARGETS_FILE"
    echo "    Create it with one target path per line."
    exit 1
fi

SUMMARY_FILE="$OUTDIR/scan_summary_${TIMESTAMP}.json"
echo "{" > "$SUMMARY_FILE"
echo '  "timestamp": "'"$TIMESTAMP"'",' >> "$SUMMARY_FILE"
echo '  "min_severity": "'"$MIN_SEVERITY"'",' >> "$SUMMARY_FILE"
echo '  "targets": [' >> "$SUMMARY_FILE"

FIRST=true
TOTAL_FINDINGS=0
TOTAL_HIGH=0
TOTAL_CRIT=0

while IFS= read -r TARGET; do
    # Skip empty lines and comments
    [[ -z "$TARGET" || "$TARGET" =~ ^# ]] && continue
    
    # Resolve path
    TARGET_PATH="$(eval echo "$TARGET")"
    if [[ ! -d "$TARGET_PATH" ]]; then
        echo "[!] Skipping missing target: $TARGET_PATH"
        continue
    fi
    
    BASENAME=$(basename "$TARGET_PATH")
    OUTFILE="$OUTDIR/${BASENAME}_${TIMESTAMP}.json"
    
    echo "[→] Scanning $BASENAME ..."
    
    # Run scan (mcp-audit exits 1 on findings, so || true)
    # Strip the "Scanning..." prefix line before saving JSON
    mcp-audit sast "$TARGET_PATH" --format json 2>/dev/null | tail -n +2 > "$OUTFILE" || true
    
    # Filter by severity + count
    if command -v jq >/dev/null 2>&1; then
        FILTERED="$OUTDIR/${BASENAME}_${TIMESTAMP}_${MIN_SEVERITY}+.json"
        jq --arg sev "$MIN_SEVERITY" '
            [.[] | select(.severity == $sev or .severity == "CRITICAL")]
        ' "$OUTFILE" > "$FILTERED" 2>/dev/null || echo "[]" > "$FILTERED"
        
        COUNT=$(jq 'length' "$FILTERED")
        HIGH=$(jq '[.[] | select(.severity == "HIGH")] | length' "$FILTERED")
        CRIT=$(jq '[.[] | select(.severity == "CRITICAL")] | length' "$FILTERED")
    else
        # Fallback: no jq, just copy raw
        cp "$OUTFILE" "$OUTDIR/${BASENAME}_${TIMESTAMP}_${MIN_SEVERITY}+.json"
        COUNT=$(grep -c '"severity"' "$OUTFILE" || true)
        HIGH=0
        CRIT=0
    fi
    
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
    TOTAL_HIGH=$((TOTAL_HIGH + HIGH))
    TOTAL_CRIT=$((TOTAL_CRIT + CRIT))
    
    if [[ "$FIRST" == "true" ]]; then
        FIRST=false
    else
        echo "," >> "$SUMMARY_FILE"
    fi
    
    cat >> "$SUMMARY_FILE" <<EOF
    {
      "target": "$BASENAME",
      "path": "$TARGET_PATH",
      "findings": $COUNT,
      "high": $HIGH,
      "critical": $CRIT,
      "output": "$OUTFILE",
      "filtered": "$FILTERED"
    }
EOF
    
    echo "    ✓ $COUNT findings ($HIGH HIGH, $CRIT CRITICAL) → $FILTERED"
done < "$TARGETS_FILE"

echo "" >> "$SUMMARY_FILE"
echo '  ],' >> "$SUMMARY_FILE"
echo '  "totals": {' >> "$SUMMARY_FILE"
echo '    "findings": '"$TOTAL_FINDINGS"',' >> "$SUMMARY_FILE"
echo '    "high": '"$TOTAL_HIGH"',' >> "$SUMMARY_FILE"
echo '    "critical": '"$TOTAL_CRIT" >> "$SUMMARY_FILE"
echo '  }' >> "$SUMMARY_FILE"
echo "}" >> "$SUMMARY_FILE"

echo ""
echo "=== Scan Complete ==="
echo "Total findings (≥$MIN_SEVERITY): $TOTAL_FINDINGS"
echo "  HIGH: $TOTAL_HIGH"
echo "  CRITICAL: $TOTAL_CRIT"
echo "Summary: $SUMMARY_FILE"
