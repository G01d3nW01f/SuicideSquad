#!/usr/bin/env bash

# ============================================================
# SuicideSquad
# Automated DAST Scanner for Local and CI Environments
# ============================================================

set -uo pipefail

VERSION="1.1.0"

# ------------------------------------------------------------
# Colors
# ------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ------------------------------------------------------------
# Default Configuration
# ------------------------------------------------------------

TARGET_LIST=""
DEPTH=5
CONCURRENCY=10
RATE=50
SCOPE="fqdn"
SEVERITY="critical,high"
OUTPUT_DIR="suicidesquad-output"
BASELINE=""
WARN_ONLY=false

ENABLE_ARJUN=true
ENABLE_DAST=true
ENABLE_CVE=true
ENABLE_HEALTHCHECK=true

CUSTOM_HEADERS=()

# ------------------------------------------------------------
# Runtime State
# ------------------------------------------------------------

FAILED_SCANS=()
COMPLETED_SCANS=()
FINDINGS=0

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

info() {
    echo -e "${BLUE}[*]${NC} $*"
}

success() {
    echo -e "${GREEN}[+]${NC} $*"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $*"
}

error() {
    echo -e "${RED}[-]${NC} $*" >&2
}

banner() {
    echo -e "${CYAN}"
    cat <<'EOF'
  ____        _      _     _       ____   ___  _   _  ____
 / ___| _   _(_) ___(_) __| | ___ / ___| / _ \| | | |/ ___|
 \___ \| | | | |/ __| |/ _` |/ _ \\___ \| | | | | | |\___ \
  ___) | |_| | | (__| | (_| |  __/ ___) | |_| | |_| | ___) |
 |____/ \__, |_|\___|_|\__,_|\___||____/ \___/ \__,_|____/
        |___/
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Automated DAST Scanner v${VERSION}${NC}"
    echo
}

# ------------------------------------------------------------
# Usage
# ------------------------------------------------------------

usage() {
    cat <<EOF
SuicideSquad v${VERSION}

Usage:
  $0 -l targets.txt [options]

Options:
  -l, --list FILE          Target list
  -d, --depth NUMBER       Crawl depth (default: 5)
  -c, --concurrency NUMBER Concurrent workers (default: 10)
  -r, --rate NUMBER        Requests per second (default: 50)
  -s, --scope SCOPE        Scope: fqdn or rdn (default: fqdn)
  -H, --header HEADER      Add custom HTTP header (repeatable)
  -S, --severity LEVELS    Nuclei severity (default: critical,high)
  -o, --output DIR         Output directory
  -b, --baseline FILE      Baseline JSONL file
  -w, --warn-only          Do not fail because of findings
      --no-arjun           Disable Arjun parameter discovery
      --no-dast            Disable DAST checks
      --no-cve             Disable CVE and exposure checks
      --skip-healthcheck   Skip dependency health checks
  -h, --help               Show this help

Exit Codes:
  0  Scan completed successfully with no findings,
     or findings were detected with --warn-only.
  1  Scan completed successfully but findings were detected.
  2  Scan execution failed or one or more scan stages failed.

Examples:
  $0 -l targets.txt
  $0 -l targets.txt -d 3 -c 5 -r 20
  $0 -l targets.txt -H "Authorization: Bearer TOKEN"
  $0 -l targets.txt -b baseline.jsonl --warn-only

EOF
}

# ------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l|--list)
            TARGET_LIST="${2:-}"
            shift 2
            ;;
        -d|--depth)
            DEPTH="${2:-}"
            shift 2
            ;;
        -c|--concurrency)
            CONCURRENCY="${2:-}"
            shift 2
            ;;
        -r|--rate)
            RATE="${2:-}"
            shift 2
            ;;
        -s|--scope)
            SCOPE="${2:-}"
            shift 2
            ;;
        -H|--header)
            CUSTOM_HEADERS+=("${2:-}")
            shift 2
            ;;
        -S|--severity)
            SEVERITY="${2:-}"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        -b|--baseline)
            BASELINE="${2:-}"
            shift 2
            ;;
        -w|--warn-only)
            WARN_ONLY=true
            shift
            ;;
        --no-arjun)
            ENABLE_ARJUN=false
            shift
            ;;
        --no-dast)
            ENABLE_DAST=false
            shift
            ;;
        --no-cve)
            ENABLE_CVE=false
            shift
            ;;
        --skip-healthcheck)
            ENABLE_HEALTHCHECK=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 2
            ;;
    esac
done

# ------------------------------------------------------------
# Input Validation
# ------------------------------------------------------------

if [[ -z "$TARGET_LIST" ]]; then
    error "Target list is required. Use -l or --list."
    exit 2
fi

if [[ ! -f "$TARGET_LIST" || ! -r "$TARGET_LIST" ]]; then
    error "Target list does not exist or is not readable: $TARGET_LIST"
    exit 2
fi

for value in "$DEPTH" "$CONCURRENCY" "$RATE"; do
    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        error "Depth, concurrency, and rate must be positive integers."
        exit 2
    fi
done

if [[ "$SCOPE" != "fqdn" && "$SCOPE" != "rdn" ]]; then
    error "Scope must be either fqdn or rdn."
    exit 2
fi

if [[ ${#CUSTOM_HEADERS[@]} -gt 0 ]]; then
    for header in "${CUSTOM_HEADERS[@]}"; do
        if [[ -z "$header" ]]; then
            error "Custom header cannot be empty."
            exit 2
        fi
    done
fi

# ------------------------------------------------------------
# Output Setup
# ------------------------------------------------------------

if ! mkdir -p "$OUTPUT_DIR"; then
    error "Failed to create output directory: $OUTPUT_DIR"
    exit 2
fi

OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)" || {
    error "Failed to resolve output directory."
    exit 2
}

# ------------------------------------------------------------
# Output Files
# ------------------------------------------------------------

TARGETS_FILE="$OUTPUT_DIR/targets.txt"
ALL_URLS="$OUTPUT_DIR/all_urls.txt"
PARAM_URLS="$OUTPUT_DIR/parameter_urls.txt"
DIRECTORY_URLS="$OUTPUT_DIR/directory_urls.txt"
PARAMS_FILE="$OUTPUT_DIR/parameters.txt"
GF_DIR="$OUTPUT_DIR/gf"
NUCLEI_DAST="$OUTPUT_DIR/nuclei_dast.jsonl"
NUCLEI_CVE="$OUTPUT_DIR/nuclei_cve.jsonl"
NUCLEI_ALL="$OUTPUT_DIR/nuclei_all.jsonl"
NEW_FINDINGS="$OUTPUT_DIR/new_findings.jsonl"
ERROR_LOG="$OUTPUT_DIR/errors.log"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"

: > "$ERROR_LOG"
: > "$NUCLEI_DAST"
: > "$NUCLEI_CVE"
: > "$NUCLEI_ALL"
: > "$NEW_FINDINGS"

# ------------------------------------------------------------
# Scan Execution Helpers
# ------------------------------------------------------------

record_failure() {
    local scan_name="$1"
    local message="$2"

    FAILED_SCANS+=("$scan_name")

    error "$scan_name failed: $message"

    printf '[%s] %s: %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" \
        "$scan_name" \
        "$message" >> "$ERROR_LOG"
}

record_success() {
    local scan_name="$1"

    COMPLETED_SCANS+=("$scan_name")
    success "$scan_name completed successfully."
}

run_scan() {
    local scan_name="$1"
    shift

    info "Running: $scan_name"

    local status=0

    "$@" || status=$?

    if [[ "$status" -eq 0 ]]; then
        record_success "$scan_name"
        return 0
    fi

    record_failure "$scan_name" "Exit code: $status"
    return 1
}

run_pipeline() {
    local scan_name="$1"
    shift

    info "Running: $scan_name"

    "$@"
    local status=$?

    if [[ "$status" -eq 0 ]]; then
        record_success "$scan_name"
        return 0
    fi

    record_failure "$scan_name" "Exit code: $status"
    return 1
}

# ------------------------------------------------------------
# Dependency Checks
# ------------------------------------------------------------

check_dependencies() {
    local required=(katana nuclei)
    local optional=(gf unfurl arjun curl jq)
    local missing=0

    info "Checking required dependencies..."

    for tool in "${required[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            error "Required dependency missing: $tool"
            missing=1
        else
            success "$tool found."
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        record_failure "Dependency Check" "Required dependencies are missing."
        return 1
    fi

    for tool in "${optional[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            warning "Optional dependency not found: $tool"
        else
            success "$tool found."
        fi
    done

    return 0
}

# ------------------------------------------------------------
# Target Preparation
# ------------------------------------------------------------

prepare_targets() {
    info "Preparing target list..."

    if ! grep -Ev '^[[:space:]]*(#|$)' "$TARGET_LIST" > "$TARGETS_FILE"; then
        record_failure "Target Preparation" "Unable to process target list."
        return 1
    fi

    if [[ ! -s "$TARGETS_FILE" ]]; then
        record_failure "Target Preparation" "No valid targets found."
        return 1
    fi

    local count
    count=$(wc -l < "$TARGETS_FILE") || {
        record_failure "Target Preparation" "Unable to count targets."
        return 1
    }

    success "Loaded $count targets."
    record_success "Target Preparation"
    return 0
}

# ------------------------------------------------------------
# HTTP Header Arguments
# ------------------------------------------------------------

build_header_args() {
    HEADER_ARGS=()

    for header in "${CUSTOM_HEADERS[@]}"; do
        HEADER_ARGS+=("-H" "$header")
    done
}

# ------------------------------------------------------------
# Katana Crawling
# ------------------------------------------------------------

run_katana() {
    info "Starting Katana crawling..."

    local status=0

    katana \
        -list "$TARGETS_FILE" \
        -d "$DEPTH" \
        -c "$CONCURRENCY" \
        -rl "$RATE" \
        -jc \
        -kf all \
        -fs "$SCOPE" \
        "${HEADER_ARGS[@]}" \
        -silent \
        -o "$ALL_URLS" || status=$?

    if [[ "$status" -ne 0 ]]; then
        record_failure "Katana Crawling" "Katana exited with code $status."
        return 1
    fi

    if [[ ! -f "$ALL_URLS" ]]; then
        record_failure "Katana Crawling" "Output file was not created."
        return 1
    fi

    record_success "Katana Crawling"
    return 0
}

# ------------------------------------------------------------
# URL Classification
# ------------------------------------------------------------

classify_urls() {
    info "Classifying discovered URLs..."

    if [[ ! -f "$ALL_URLS" ]]; then
        record_failure "URL Classification" "Katana output is missing."
        return 1
    fi

    if ! grep -E '\?.+=' "$ALL_URLS" | sort -u > "$PARAM_URLS"; then
        # An empty result is valid; check the source file separately.
        if [[ ! -s "$ALL_URLS" ]]; then
            record_failure "URL Classification" "No crawl output available."
            return 1
        fi
        : > "$PARAM_URLS"
    fi

    if ! grep -Ev '\?.+=' "$ALL_URLS" | sort -u > "$DIRECTORY_URLS"; then
        if [[ ! -s "$ALL_URLS" ]]; then
            record_failure "URL Classification" "No crawl output available."
            return 1
        fi
        : > "$DIRECTORY_URLS"
    fi

    record_success "URL Classification"
    return 0
}

# ------------------------------------------------------------
# Parameter Extraction
# ------------------------------------------------------------

extract_parameters() {
    info "Extracting parameters..."

    if [[ ! -s "$PARAM_URLS" ]]; then
        warning "No parameter URLs found. Parameter extraction skipped."
        record_success "Parameter Extraction (No Input)"
        return 0
    fi

    if ! command -v unfurl >/dev/null 2>&1; then
        record_failure "Parameter Extraction" "unfurl is not installed."
        return 1
    fi

    if ! unfurl keys < "$PARAM_URLS" | sort -u > "$PARAMS_FILE"; then
        record_failure "Parameter Extraction" "unfurl execution failed."
        return 1
    fi

    record_success "Parameter Extraction"
    return 0
}

# ------------------------------------------------------------
# Arjun Parameter Discovery
# ------------------------------------------------------------

run_arjun() {
    if [[ "$ENABLE_ARJUN" != true ]]; then
        info "Arjun discovery disabled."
        return 0
    fi

    if ! command -v arjun >/dev/null 2>&1; then
        record_failure "Arjun Parameter Discovery" "arjun is not installed."
        return 1
    fi

    if [[ ! -s "$TARGETS_FILE" ]]; then
        record_failure "Arjun Parameter Discovery" "Target list is empty."
        return 1
    fi

    info "Starting Arjun parameter discovery..."

    local status=0

    arjun \
        -i "$TARGETS_FILE" \
        -oJ "$OUTPUT_DIR/arjun.json" \
        -t "$CONCURRENCY" || status=$?

    if [[ "$status" -ne 0 ]]; then
        record_failure "Arjun Parameter Discovery" "Arjun exited with code $status."
        return 1
    fi

    if [[ ! -f "$OUTPUT_DIR/arjun.json" ]]; then
        record_failure "Arjun Parameter Discovery" "Output file was not created."
        return 1
    fi

    record_success "Arjun Parameter Discovery"
    return 0
}

# ------------------------------------------------------------
# GF Pattern Classification
# ------------------------------------------------------------

run_gf() {
    if ! command -v gf >/dev/null 2>&1; then
        record_failure "GF Classification" "gf is not installed."
        return 1
    fi

    if [[ ! -s "$PARAM_URLS" ]]; then
        info "No parameter URLs available. GF classification skipped."
        record_success "GF Classification (No Input)"
        return 0
    fi

    mkdir -p "$GF_DIR" || {
        record_failure "GF Classification" "Unable to create output directory."
        return 1
    }

    local patterns=(
        ssrf
        sqli
        xss
        lfi
        redirect
        rce
        idor
        ssti
    )

    local failed=0

    for pattern in "${patterns[@]}"; do
        info "Running GF pattern: $pattern"

        if gf "$pattern" < "$PARAM_URLS" > "$GF_DIR/${pattern}.txt"; then
            success "GF pattern completed: $pattern"
        else
            record_failure "GF: $pattern" "Pattern execution failed."
            failed=1
        fi
    done

    if [[ "$failed" -eq 0 ]]; then
        record_success "GF Classification"
        return 0
    fi

    return 1
}

# ------------------------------------------------------------
# Nuclei DAST
# ------------------------------------------------------------

run_nuclei_dast() {
    if [[ "$ENABLE_DAST" != true ]]; then
        info "DAST checks disabled."
        return 0
    fi

    info "Starting Nuclei DAST scan..."

    local status=0

    nuclei \
        -l "$TARGETS_FILE" \
        -tags dast \
        -severity "$SEVERITY" \
        -c "$CONCURRENCY" \
        -rl "$RATE" \
        -jsonl \
        "${HEADER_ARGS[@]}" \
        -o "$NUCLEI_DAST" || status=$?

    if [[ "$status" -ne 0 ]]; then
        record_failure "Nuclei DAST" "Nuclei exited with code $status."
        return 1
    fi

    if [[ ! -f "$NUCLEI_DAST" ]]; then
        record_failure "Nuclei DAST" "Output file was not created."
        return 1
    fi

    record_success "Nuclei DAST"
    return 0
}

# ------------------------------------------------------------
# Nuclei CVE and Exposure Scan
# ------------------------------------------------------------

run_nuclei_cve() {
    if [[ "$ENABLE_CVE" != true ]]; then
        info "CVE and exposure checks disabled."
        return 0
    fi

    info "Starting Nuclei CVE and exposure scan..."

    local status=0

    nuclei \
        -l "$TARGETS_FILE" \
        -tags cve,exposure,misconfig,default-login \
        -severity "$SEVERITY" \
        -c "$CONCURRENCY" \
        -rl "$RATE" \
        -jsonl \
        "${HEADER_ARGS[@]}" \
        -o "$NUCLEI_CVE" || status=$?

    if [[ "$status" -ne 0 ]]; then
        record_failure "Nuclei CVE and Exposure" "Nuclei exited with code $status."
        return 1
    fi

    if [[ ! -f "$NUCLEI_CVE" ]]; then
        record_failure "Nuclei CVE and Exposure" "Output file was not created."
        return 1
    fi

    record_success "Nuclei CVE and Exposure"
    return 0
}

# ------------------------------------------------------------
# Result Aggregation
# ------------------------------------------------------------

aggregate_results() {
    info "Aggregating scan results..."

    if ! cat "$NUCLEI_DAST" "$NUCLEI_CVE" > "$NUCLEI_ALL"; then
        record_failure "Result Aggregation" "Unable to combine Nuclei output."
        return 1
    fi

    if [[ -s "$NUCLEI_ALL" ]]; then
        FINDINGS=$(wc -l < "$NUCLEI_ALL") || {
            record_failure "Result Aggregation" "Unable to count findings."
            return 1
        }
    else
        FINDINGS=0
    fi

    success "Total findings: $FINDINGS"
    record_success "Result Aggregation"
    return 0
}

# ------------------------------------------------------------
# Baseline Comparison
# ------------------------------------------------------------

compare_baseline() {
    if [[ -z "$BASELINE" ]]; then
        cp "$NUCLEI_ALL" "$NEW_FINDINGS" || {
            record_failure "Baseline Comparison" "Unable to copy findings."
            return 1
        }

        record_success "Baseline Comparison (No Baseline)"
        return 0
    fi

    if [[ ! -f "$BASELINE" || ! -r "$BASELINE" ]]; then
        record_failure "Baseline Comparison" "Baseline file does not exist or is not readable."
        return 1
    fi

    info "Comparing results with baseline..."

    if ! grep -F -x -v -f "$BASELINE" "$NUCLEI_ALL" > "$NEW_FINDINGS"; then
        local status=$?

        # grep returns 1 when no new findings are found.
        if [[ "$status" -ne 1 ]]; then
            record_failure "Baseline Comparison" "grep execution failed."
            return 1
        fi
    fi

    record_success "Baseline Comparison"
    return 0
}

# ------------------------------------------------------------
# Final Summary
# ------------------------------------------------------------

write_summary() {
    local scan_status="SCAN COMPLETED"
    local failed_count="${#FAILED_SCANS[@]}"
    local completed_count="${#COMPLETED_SCANS[@]}"

    if [[ "$failed_count" -gt 0 ]]; then
        scan_status="SCAN COMPLETED WITH ERRORS"
    fi

    {
        echo "========================================"
        echo "SuicideSquad Scan Summary"
        echo "========================================"
        echo "Version: $VERSION"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Status: $scan_status"
        echo "Targets: $(wc -l < "$TARGETS_FILE" 2>/dev/null || echo 0)"
        echo "Findings: $FINDINGS"
        echo "Completed stages: $completed_count"
        echo "Failed stages: $failed_count"
        echo

        if [[ "$failed_count" -gt 0 ]]; then
            echo "Failed stages:"
            for scan in "${FAILED_SCANS[@]}"; do
                echo "  - $scan"
            done
            echo
        fi

        echo "Output directory: $OUTPUT_DIR"
        echo "Error log: $ERROR_LOG"
        echo "========================================"
    } > "$SUMMARY_FILE" || {
        record_failure "Summary Generation" "Unable to write summary file."
        return 1
    }

    cat "$SUMMARY_FILE"
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

main() {
    banner

    build_header_args

    info "Starting SuicideSquad..."
    echo

    if [[ "$ENABLE_HEALTHCHECK" == true ]]; then
        if ! check_dependencies; then
            write_summary || true
            exit 2
        fi
    fi

    if ! prepare_targets; then
        write_summary || true
        exit 2
    fi

    # Run each stage independently.
    # A failed stage is recorded and the remaining stages are attempted
    # whenever their required input is available.

    run_katana || true

    if [[ -f "$ALL_URLS" ]]; then
        classify_urls || true
    else
        record_failure "URL Classification" "Skipped because Katana output is unavailable."
    fi

    if [[ -f "$PARAM_URLS" ]]; then
        extract_parameters || true
    else
        record_failure "Parameter Extraction" "Skipped because parameter URL output is unavailable."
    fi

    run_arjun || true

    if [[ -f "$PARAM_URLS" ]]; then
        run_gf || true
    else
        record_failure "GF Classification" "Skipped because parameter URL output is unavailable."
    fi

    run_nuclei_dast || true
    run_nuclei_cve || true

    aggregate_results || true
    compare_baseline || true

    echo
    info "Generating final summary..."

    write_summary || true

    echo

    if [[ "${#FAILED_SCANS[@]}" -gt 0 ]]; then
        error "SCAN COMPLETED WITH ERRORS"
        error "Failed stages: ${#FAILED_SCANS[@]}"

        for scan in "${FAILED_SCANS[@]}"; do
            error " - $scan"
        done

        error "Check the error log: $ERROR_LOG"
        error "The scan results may be incomplete."
        exit 2
    fi

    if [[ "$FINDINGS" -gt 0 ]]; then
        warning "SCAN COMPLETED - FINDINGS DETECTED"
        warning "Total findings: $FINDINGS"

        if [[ "$WARN_ONLY" == true ]]; then
            warning "Warn-only mode enabled. Returning exit code 0."
            exit 0
        fi

        exit 1
    fi

    success "SCAN COMPLETED"
    success "No findings detected."
    exit 0
}

main "$@"
