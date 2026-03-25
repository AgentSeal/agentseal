#!/bin/bash
set -e

PATH_ARG="${1:-.}"
CONFIG_ARG="$2"
FAIL_ON="${3:-danger}"
NO_REGISTRY="${4:-false}"
VERBOSE="${5:-false}"

SARIF_PATH="/github/workspace/agentseal.sarif"
JSON_PATH="/tmp/agentseal-report.json"

# Build command as array (no eval, no injection risk)
CMD=(agentseal guard --path "$PATH_ARG" --output json --save "$JSON_PATH" --fail-on "$FAIL_ON")
[ -n "$CONFIG_ARG" ] && CMD+=(--config "$CONFIG_ARG")
[ "$NO_REGISTRY" = "true" ] && CMD+=(--no-registry)
[ "$VERBOSE" = "true" ] && CMD+=(--verbose)

# Single scan run — JSON output captures everything
"${CMD[@]}" || true
EXIT_CODE=${PIPESTATUS[0]:-$?}

# Convert JSON → SARIF (--from-json flag reads saved report, no re-scan)
agentseal guard --from-json "$JSON_PATH" --output sarif --save "$SARIF_PATH" 2>/dev/null || true

# Terminal output for Actions log
agentseal guard --from-json "$JSON_PATH" --output terminal 2>/dev/null || true

# Write PR summary from saved JSON
echo "## AgentSeal Guard Results" >> "$GITHUB_STEP_SUMMARY"
python3 -c "
import sys, json
try:
    r = json.load(open('$JSON_PATH'))
    d = r.get('summary', {})
    print(f'| Metric | Count |')
    print(f'|--------|-------|')
    print(f'| Dangers | {d.get(\"total_dangers\", 0)} |')
    print(f'| Warnings | {d.get(\"total_warnings\", 0)} |')
    print(f'| Safe | {d.get(\"total_safe\", 0)} |')
except Exception:
    print('Report unavailable')
" >> "$GITHUB_STEP_SUMMARY" || true

# Set outputs
echo "sarif-file=$SARIF_PATH" >> "$GITHUB_OUTPUT"
echo "exit-code=$EXIT_CODE" >> "$GITHUB_OUTPUT"

exit "$EXIT_CODE"
