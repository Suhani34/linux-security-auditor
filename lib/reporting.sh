#!/usr/bin/env bash

find_previous_report() {

    local candidate
    local candidate_mode

    PREVIOUS_REPORT=""

    while IFS= read -r candidate; do

        if [[ -z "$candidate" ]]; then
            continue
        fi

        candidate_mode="$(
            awk -F ':' '
                {
                    key=$1
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)

                    if (key == "AUDIT MODE") {
                        value=$2
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                        print value
                        exit
                    }
                }
            ' "$candidate" 2>/dev/null
        )"

        if [[ "$candidate_mode" == "$AUDIT_MODE" ]]; then

            PREVIOUS_REPORT="$candidate"
            break

        fi

    done < <(
        find "$REPORT_DIR" \
            -maxdepth 1 \
            -type f \
            -name "security-audit-${REPORT_HOSTNAME}-*.txt" \
            -printf '%T@|%p\n' 2>/dev/null |
        sort -t'|' -k1,1nr |
        cut -d'|' -f2-
    )
}
get_report_value() {

    local report_file="$1"
    local label="$2"

    awk -F ':' -v target="$label" '

        {
            key=$1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)

            if (key == target) {
                value=$2
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

                print value
                exit
            }
        }

    ' "$report_file" 2>/dev/null
}

initialize_report() {

    if ! mkdir -p "$REPORT_DIR"; then
        echo "[ERROR] Could not create report directory: $REPORT_DIR" >&2
        return 1
    fi
   find_previous_report

    REPORT_FILE="$REPORT_DIR/security-audit-${REPORT_HOSTNAME}-${REPORT_TIMESTAMP}.txt"
    JSON_REPORT_FILE="$REPORT_DIR/security-audit-${REPORT_HOSTNAME}-${REPORT_TIMESTAMP}.json"

    if ! touch "$REPORT_FILE"; then
        echo "[ERROR] Could not create report file: $REPORT_FILE" >&2
        return 1
    fi

    chmod 600 "$REPORT_FILE" 2>/dev/null || true
    return 0
}

enable_report_logging() {

    exec > >(tee -a "$REPORT_FILE") 2>&1
}

json_escape() {
    local value="$1"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"

    printf '%s' "$value"
}

calculate_security_score() {

    local warning_points
    local critical_points
    local total_penalty

    warning_points=$((WARNING_COUNT * WARNING_PENALTY))
    critical_points=$((CRITICAL_COUNT * CRITICAL_PENALTY))
    total_penalty=$((warning_points + critical_points))

    SECURITY_SCORE=$((MAX_SECURITY_SCORE - total_penalty))

    if (( SECURITY_SCORE < 0 )); then
        SECURITY_SCORE=0
    fi

    if (( SECURITY_SCORE >= 90 )); then
        SECURITY_RATING="STRONG"

    elif (( SECURITY_SCORE >= 75 )); then
        SECURITY_RATING="GOOD"

    elif (( SECURITY_SCORE >= 60 )); then
        SECURITY_RATING="NEEDS IMPROVEMENT"

    elif (( SECURITY_SCORE >= 40 )); then
        SECURITY_RATING="WEAK"
    else
        SECURITY_RATING="POOR"
    fi
}

print_recommendations() {

    local recommendation_number=1
    local recommendation

    echo
    echo "============================================================"
    echo "                 REMEDIATION RECOMMENDATIONS"
    echo "============================================================"
    echo

    if (( ${#RECOMMENDATIONS[@]} == 0 )); then

        echo "[PASS] No remediation recommendations were generated."

    else

        for recommendation in "${RECOMMENDATIONS[@]}"; do

            echo "$recommendation_number. $recommendation"
            echo

            ((recommendation_number+=1))

        done
    fi

    echo "============================================================"
}

print_audit_comparison() {

    local previous_score_raw
    local previous_score
    local previous_warnings
    local previous_criticals

    local score_change
    local warning_change
    local critical_change

    local security_trend

    echo
    echo "============================================================"
    echo "                  AUDIT COMPARISON"
    echo "============================================================"
    echo

    if [[ -z "$PREVIOUS_REPORT" || ! -f "$PREVIOUS_REPORT" ]]; then

        echo "[INFO] No previous compatible $AUDIT_MODE audit report was found."
        echo "[INFO] A comparison will be available after another $AUDIT_MODE audit is completed"

        echo
        echo "============================================================"

        return 0
    fi

    previous_score_raw="$(get_report_value "$PREVIOUS_REPORT" "SECURITY SCORE")"
    previous_warnings="$(get_report_value "$PREVIOUS_REPORT" "WARNING")"
    previous_criticals="$(get_report_value "$PREVIOUS_REPORT" "CRITICAL")"

    previous_score="${previous_score_raw%%/*}"

    if [[ ! "$previous_score" =~ ^[0-9]+$ ]] ||
       [[ ! "$previous_warnings" =~ ^[0-9]+$ ]] ||
       [[ ! "$previous_criticals" =~ ^[0-9]+$ ]]; then

        echo "[WARNING] The previous report could not be parsed reliably."
        echo "[INFO] Historical comparison was skipped."

        echo
        echo "============================================================"
        return 0
    fi

    score_change=$((SECURITY_SCORE - previous_score))
    warning_change=$((WARNING_COUNT - previous_warnings))
    critical_change=$((CRITICAL_COUNT - previous_criticals))

    if (( score_change > 0 )); then

        security_trend="IMPROVED"

    elif (( score_change < 0 )); then

        security_trend="REGRESSED"

    else

        security_trend="UNCHANGED"

    fi
    echo "Previous report     : $PREVIOUS_REPORT"
    echo "Audit mode          : $AUDIT_MODE"

    echo
    echo "Previous score      : $previous_score/100"
    echo "Current score       : $SECURITY_SCORE/100"

    if (( score_change > 0 )); then
        echo "Score change        : +$score_change points"
    else
        echo "Score change        : $score_change points"
    fi

    echo "Security trend      : $security_trend"

    echo
    echo "Previous warnings   : $previous_warnings"
    echo "Current warnings    : $WARNING_COUNT"

    if (( warning_change > 0 )); then
        echo "Warning change      : +$warning_change"
    else
        echo "Warning change      : $warning_change"
    fi

    echo
    echo "Previous criticals  : $previous_criticals"
    echo "Current criticals   : $CRITICAL_COUNT"

    if (( critical_change > 0 )); then
        echo "Critical change     : +$critical_change"
    else
        echo "Critical change     : $critical_change"
    fi

    echo
    echo "============================================================"
}
generate_json_report() {

    local total_findings
    local warning_points
    local critical_points
    local total_penalty

    local previous_score_raw=""
    local previous_score=""
    local previous_warnings=""
    local previous_criticals=""

    local score_change=""
    local warning_change=""
    local critical_change=""
    local security_trend=""

    local comparison_available="false"

    local finding_index
    local recommendation_index

    local temp_file="${JSON_REPORT_FILE}.tmp"

    total_findings=$((PASS_COUNT + INFO_COUNT + WARNING_COUNT + CRITICAL_COUNT))

    warning_points=$((WARNING_COUNT * WARNING_PENALTY))
    critical_points=$((CRITICAL_COUNT * CRITICAL_PENALTY))
    total_penalty=$((warning_points + critical_points))

    calculate_security_score

    if [[ -n "$PREVIOUS_REPORT" && -f "$PREVIOUS_REPORT" ]]; then

        previous_score_raw="$(
            get_report_value "$PREVIOUS_REPORT" "SECURITY SCORE"
        )"

        previous_warnings="$(
            get_report_value "$PREVIOUS_REPORT" "WARNING"
       )"

        previous_criticals="$(
            get_report_value "$PREVIOUS_REPORT" "CRITICAL"
        )"

        previous_score="${previous_score_raw%%/*}"

        if [[ "$previous_score" =~ ^[0-9]+$ ]] &&
           [[ "$previous_warnings" =~ ^[0-9]+$ ]] &&
           [[ "$previous_criticals" =~ ^[0-9]+$ ]]; then

            comparison_available="true"

            score_change=$((SECURITY_SCORE - previous_score))
            warning_change=$((WARNING_COUNT - previous_warnings))
            critical_change=$((CRITICAL_COUNT - previous_criticals))

            if (( score_change > 0 )); then
                security_trend="IMPROVED"

            elif (( score_change < 0 )); then

                security_trend="REGRESSED"

            else

                security_trend="UNCHANGED"

            fi

        fi

    fi

   if ! : > "$temp_file"; then

        echo "[WARNING] Could not create temporary JSON report: $temp_file"
        return 1
    fi

    {
        echo "{"

        printf '  "schema_version": "1.0",\n'

        printf '  "generated_at": "%s",\n' \
            "$(json_escape "$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')")"


        echo '  "audit": {'

        printf '    "hostname": "%s",\n' \
            "$(json_escape "$REPORT_HOSTNAME")"

        printf '    "audit_mode": "%s",\n' \
            "$(json_escape "$AUDIT_MODE")"

        printf '    "run_by": "%s",\n' \
            "$(json_escape "$INVOKING_USER")"
        printf '    "effective_as": "%s",\n' \
            "$(json_escape "$CURRENT_USER")"

        printf '    "operating_system": "%s",\n' \
            "$(json_escape "$OS_NAME")"

        printf '    "kernel": "%s",\n' \
            "$(json_escape "$KERNEL")"

        printf '    "architecture": "%s",\n' \
            "$(json_escape "$ARCHITECTURE")"

        printf '    "source_text_report": "%s"\n' \
            "$(json_escape "$REPORT_FILE")"

        echo "  },"

        echo '  "summary": {'

        printf '    "total_findings": %d,\n' "$total_findings"
        printf '    "pass": %d,\n' "$PASS_COUNT"
        printf '    "info": %d,\n' "$INFO_COUNT"
        printf '    "warning": %d,\n' "$WARNING_COUNT"
        printf '    "critical": %d,\n' "$CRITICAL_COUNT"

        printf '    "warning_penalty": %d,\n' "$warning_points"
        printf '    "critical_penalty": %d,\n' "$critical_points"
        printf '    "total_penalty": %d,\n' "$total_penalty"

        printf '    "security_score": %d,\n' "$SECURITY_SCORE"
        printf '    "maximum_security_score": %d,\n' "$MAX_SECURITY_SCORE"

       printf '    "rating": "%s"\n' \
            "$(json_escape "$SECURITY_RATING")"

        echo "  },"

        echo '  "findings": ['

        for ((finding_index=0;
             finding_index<${#FINDING_MESSAGES[@]};
              finding_index++))
        do

            echo "    {"

            printf '      "severity": "%s",\n' \
                "$(json_escape "${FINDING_SEVERITIES[$finding_index]}")"

            printf '      "message": "%s"\n' \
                "$(json_escape "${FINDING_MESSAGES[$finding_index]}")"

            if (( finding_index < ${#FINDING_MESSAGES[@]} - 1 )); then
                echo "    },"
            else
                echo "    }"
            fi

        done
        echo "  ],"
echo '  "recommendations": ['

        for ((recommendation_index=0;
              recommendation_index<${#RECOMMENDATIONS[@]};
              recommendation_index++))
        do

            printf '    "%s"' \
                "$(json_escape "${RECOMMENDATIONS[$recommendation_index]}")"

            if (( recommendation_index < ${#RECOMMENDATIONS[@]} - 1 )); then
                echo ","
            else
                echo
            fi

        done

        echo "  ],"
        echo '  "comparison": {'

        if [[ "$comparison_available" == "true" ]]; then

            echo '    "available": true,'

            printf '    "previous_report": "%s",\n' \
                "$(json_escape "$PREVIOUS_REPORT")"

            printf '    "previous_score": %d,\n' "$previous_score"
            printf '    "current_score": %d,\n' "$SECURITY_SCORE"
            printf '    "score_change": %d,\n' "$score_change"

            printf '    "previous_warnings": %d,\n' "$previous_warnings"
            printf '    "current_warnings": %d,\n' "$WARNING_COUNT"
            printf '    "warning_change": %d,\n' "$warning_change"

            printf '    "previous_criticals": %d,\n' "$previous_criticals"
            printf '    "current_criticals": %d,\n' "$CRITICAL_COUNT"
            printf '    "critical_change": %d,\n' "$critical_change"
           printf '    "security_trend": "%s"\n' \
                "$(json_escape "$security_trend")"

        else

            echo '    "available": false,'
            echo '    "previous_report": null,'
            echo '    "security_trend": null'

        fi

        echo "  }"

        echo "}"

    } > "$temp_file"

    if ! mv "$temp_file" "$JSON_REPORT_FILE"; then

        echo "[WARNING] Could not finalize JSON report"
        rm -f "$temp_file"
        return 1

    fi

    chmod 600 "$JSON_REPORT_FILE" 2>/dev/null || true

    echo "[INFO] JSON audit report saved to: $JSON_REPORT_FILE"

    return 0
} 

print_summary() {
    local total_findings
    local warning_points
    local critical_points
    local total_penalty

    total_findings=$((PASS_COUNT + INFO_COUNT + WARNING_COUNT + CRITICAL_COUNT))
    warning_points=$((WARNING_COUNT * WARNING_PENALTY))
    critical_points=$((CRITICAL_COUNT * CRITICAL_PENALTY))
    total_penalty=$((warning_points + critical_points))

    calculate_security_score

    echo
    echo "=================================================="
    echo "                 AUDIT SUMMARY"
    echo "=================================================="
    echo

    echo "Total Audit Results: $total_findings"
    echo

    echo "PASS               : $PASS_COUNT"
    echo "WARNING            : $WARNING_COUNT"
    echo "CRITICAL           : $CRITICAL_COUNT"
    echo "INFO               : $INFO_COUNT"
    echo
    echo "Warning Penalty    : -$warning_points"
    echo "Critical Peanlty   : -$critical_points"
    echo "Total Penalty      : -$total_penalty"

    echo
    echo "SECURITY SCORE      : $SECURITY_SCORE/$MAX_SECURITY_SCORE"
    echo "RATING              : $SECURITY_RATING"
    echo "AUDIT MODE          : $AUDIT_MODE"

    if [[ "$AUDIT_MODE" == "PARTIAL" ]]; then
        echo
        info "This was a partial security audit."
        info "Run the auditor with sudo for checks that require elevated privileges"
    fi

    echo
    info "The security score is a heuristic assessment based on checks performed by the auditor"

    echo
    echo "============================================================"
}






