# SuicideSquad

**Automated DAST Scanner for Local and CI Environments**

SuicideSquad is an automated security scanning tool written in Bash. It combines web crawling, parameter discovery, vulnerability pattern classification, and Nuclei-based security scanning into a single workflow.

It is designed to help security researchers and penetration testers identify potential web application vulnerabilities efficiently.

---

## Features

- **Automated Web Crawling**
  - Uses Katana to discover URLs and endpoints.
  - Supports configurable crawl depth, concurrency, and request rate.
  - Supports FQDN and RDN scope settings.

- **Parameter Discovery**
  - Extracts parameterized URLs.
  - Extracts parameter names using unfurl.
  - Supports optional hidden parameter discovery using Arjun.

- **Vulnerability Pattern Classification**
  - Uses gf to classify parameterized URLs.
  - Supports the following patterns:
    - SSRF
    - SQL Injection
    - XSS
    - LFI
    - Open Redirect
    - RCE
    - IDOR
    - SSTI

- **Automated Vulnerability Scanning**
  - Uses Nuclei for DAST checks.
  - Supports CVE, exposure, misconfiguration, and default-login checks.
  - Allows configurable severity filtering.

- **Baseline Comparison**
  - Compares current findings against a previous JSONL baseline.
  - Separates newly detected findings from existing findings.

- **Custom HTTP Headers**
  - Supports custom headers for authenticated scanning.
  - Multiple headers can be specified.

- **Execution Status Monitoring**
  - Checks the exit status of individual scan stages.
  - Records failed stages and their error messages.
  - Continues independent scan stages when possible.
  - Clearly distinguishes successful scans from scans with errors.
  - Returns a non-zero exit code when scan execution fails.

- **CI/CD Friendly**
  - Provides predictable exit codes.
  - Supports warning-only mode for findings.
  - Generates a scan summary and error log.

---

## Requirements

### Required Dependencies

| Tool | Purpose |
|---|---|
| [Katana](https://github.com/projectdiscovery/katana) | Web crawling |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning |

### Optional Dependencies

| Tool | Purpose |
|---|---|
| [gf](https://github.com/tomnomnom/gf) | URL pattern classification |
| [unfurl](https://github.com/tomnomnom/unfurl) | URL parameter extraction |
| [Arjun](https://github.com/s0md3v/Arjun) | Hidden parameter discovery |
| curl | HTTP-related utilities |
| jq | JSON processing |

Install the required tools and ensure they are available in your system's PATH.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/USERNAME/SuicideSquad.git
cd SuicideSquad
```

Make the script executable:

```bash
chmod +x SuicideSquad
```

Verify that the required dependencies are installed:

```bash
katana -version
nuclei -version
```

---

## Usage

Basic usage:

```bash
./SuicideSquad -l targets.txt
```

The target list should contain one target URL per line.

Example:

```text
https://example.com
https://test.example.com
https://api.example.com
```

Lines beginning with `#` and blank lines are ignored.

---

## Options

| Option | Description | Default |
|---|---|---|
| `-l, --list` | Target list file | Required |
| `-d, --depth` | Crawl depth | `5` |
| `-c, --concurrency` | Concurrent workers | `10` |
| `-r, --rate` | Requests per second | `50` |
| `-s, --scope` | Crawl scope: `fqdn` or `rdn` | `fqdn` |
| `-H, --header` | Custom HTTP header | None |
| `-S, --severity` | Nuclei severity levels | `critical,high` |
| `-o, --output` | Output directory | `suicidesquad-output` |
| `-b, --baseline` | Baseline JSONL file | None |
| `-w, --warn-only` | Return success when findings are detected | Disabled |
| `--no-arjun` | Disable Arjun parameter discovery | Enabled |
| `--no-dast` | Disable Nuclei DAST checks | Enabled |
| `--no-cve` | Disable CVE and exposure checks | Enabled |
| `--skip-healthcheck` | Skip dependency health checks | Disabled |
| `-h, --help` | Display help | - |

---

## Examples

### Basic Scan

```bash
./SuicideSquad -l targets.txt
```

### Custom Crawl Depth

```bash
./SuicideSquad -l targets.txt -d 3
```

### Custom Concurrency and Rate

```bash
./SuicideSquad -l targets.txt -c 5 -r 20
```

### Authenticated Scanning

Specify custom HTTP headers:

```bash
./SuicideSquad \
  -l targets.txt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Custom-Header: VALUE"
```

### Change Nuclei Severity

```bash
./SuicideSquad -l targets.txt -S critical,high,medium
```

### Disable Arjun

```bash
./SuicideSquad -l targets.txt --no-arjun
```

### Disable DAST Checks

```bash
./SuicideSquad -l targets.txt --no-dast
```

### Disable CVE and Exposure Checks

```bash
./SuicideSquad -l targets.txt --no-cve
```

### Use a Custom Output Directory

```bash
./SuicideSquad -l targets.txt -o results
```

### Baseline Comparison

```bash
./SuicideSquad \
  -l targets.txt \
  -b previous-findings.jsonl
```

### Warning-Only Mode

```bash
./SuicideSquad -l targets.txt --warn-only
```

In warning-only mode, detected findings do not cause the script to return exit code `1`.

**Important:** Warning-only mode does not suppress scan execution errors. If a scan stage fails, the script still returns exit code `2`.

---

## Scan Workflow

SuicideSquad executes the following workflow:

```text
                 Target List
                      |
                      v
              Dependency Check
                      |
                      v
               Target Preparation
                      |
                      v
                Katana Crawling
                      |
                      v
               URL Classification
                      |
             +--------+--------+
             |                 |
             v                 v
       Parameter URLs     Directory URLs
             |
       +-----+------+
       |            |
       v            v
     Unfurl       Arjun
       |            |
       v            v
 Parameter      Hidden Parameter
 Extraction      Discovery
       |
       v
  GF Classification
       |
       +----------------------+
       |                      |
       v                      v
   Nuclei DAST          Nuclei CVE
       |                      |
       +----------+-----------+
                  |
                  v
           Result Aggregation
                  |
                  v
           Baseline Comparison
                  |
                  v
            Final Summary
                  |
                  v
           Execution Status
```

---

## Output Structure

The default output directory is `suicidesquad-output/`.

```text
suicidesquad-output/
├── targets.txt
├── all_urls.txt
├── parameter_urls.txt
├── directory_urls.txt
├── parameters.txt
├── gf/
│   ├── ssrf.txt
│   ├── sqli.txt
│   ├── xss.txt
│   ├── lfi.txt
│   ├── redirect.txt
│   ├── rce.txt
│   ├── idor.txt
│   └── ssti.txt
├── arjun.json
├── nuclei_dast.jsonl
├── nuclei_cve.jsonl
├── nuclei_all.jsonl
├── new_findings.jsonl
├── errors.log
└── summary.txt
```

| File | Description |
|---|---|
| `targets.txt` | Processed target list |
| `all_urls.txt` | URLs discovered by Katana |
| `parameter_urls.txt` | URLs containing query parameters |
| `directory_urls.txt` | URLs without query parameters |
| `parameters.txt` | Extracted parameter names |
| `gf/` | URLs classified by vulnerability patterns |
| `arjun.json` | Arjun parameter discovery results |
| `nuclei_dast.jsonl` | Nuclei DAST findings |
| `nuclei_cve.jsonl` | Nuclei CVE and exposure findings |
| `nuclei_all.jsonl` | Combined Nuclei findings |
| `new_findings.jsonl` | Findings not present in the baseline |
| `errors.log` | Scan execution errors |
| `summary.txt` | Final scan summary |

Some output files are created only when their corresponding scan stages execute.

---

## Scan Completion Status

SuicideSquad tracks the execution status of individual scan stages.

### Successful Completion

```text
[+] SCAN COMPLETED
[+] No findings detected.
```

This indicates that all executed scan stages completed without reported execution errors.

### Findings Detected

```text
[!] SCAN COMPLETED - FINDINGS DETECTED
[!] Total findings: 3
```

The scan completed without execution errors, but potential vulnerabilities were detected.

### Scan Completed With Errors

```text
[-] SCAN COMPLETED WITH ERRORS
[-] Failed stages: 2
[-]  - Katana Crawling
[-]  - Nuclei DAST
[-] Check the error log: suicidesquad-output/errors.log
[-] The scan results may be incomplete.
```

This indicates that one or more scan stages failed.

**Important:** A scan that reports `SCAN COMPLETED WITH ERRORS` must not be treated as a fully successful scan. Its results may be incomplete.

---

## Exit Codes

SuicideSquad uses the following exit codes:

| Exit Code | Meaning |
|---|---|
| `0` | Scan completed successfully with no findings, or findings were detected with `--warn-only` |
| `1` | Scan completed successfully and findings were detected |
| `2` | Scan execution failed, a required dependency is missing, or one or more scan stages failed |

### CI/CD Integration

Example:

```bash
./SuicideSquad -l targets.txt --warn-only

STATUS=$?

if [ "$STATUS" -eq 0 ]; then
    echo "Scan completed successfully."
elif [ "$STATUS" -eq 1 ]; then
    echo "Findings detected."
elif [ "$STATUS" -eq 2 ]; then
    echo "Scan execution failed or results may be incomplete."
fi
```

For reliable CI/CD integration, treat exit code `2` as an execution failure.

---

## Baseline Comparison

Baseline comparison helps identify findings that were not present in a previous scan.

Generate a baseline from a previous scan:

```bash
cp suicidesquad-output/nuclei_all.jsonl baseline.jsonl
```

Use it in a subsequent scan:

```bash
./SuicideSquad \
  -l targets.txt \
  -b baseline.jsonl
```

New findings are written to:

```text
new_findings.jsonl
```

**Note:** Baseline comparison currently uses exact JSONL line matching. Changes in JSON field ordering or variable values may cause an existing finding to be reported as new.

---

## Error Handling

SuicideSquad records failed scan stages in `errors.log`.

The script attempts to continue independent scan stages when possible, even if an earlier stage fails.

For example:

- If Katana fails, URL-dependent stages may be skipped.
- If Arjun fails, other independent scan stages can still run.
- If Nuclei DAST fails, the CVE scan may still run.
- If one GF pattern fails, the remaining patterns are still attempted.

At the end of execution, the script reports all recorded failures.

This behavior helps preserve partial scan results while clearly indicating that the overall scan was not fully successful.

---

## Security Considerations

- Only scan systems for which you have explicit authorization.
- Ensure that all targets are within the intended testing scope.
- Authenticated scans may expose sensitive information in output files.
- Treat scan results, HTTP headers, and baseline files as sensitive data.
- Avoid placing authentication tokens directly in shell history.
- Adjust concurrency and request rates to avoid overloading target systems.
- Review Nuclei findings manually before making security decisions.

SuicideSquad is an automated testing tool. Its results should not be considered proof that a system is secure or vulnerable without further verification.

---

## Limitations

- Scan coverage depends on the capabilities and configuration of the underlying tools.
- Crawling cannot guarantee discovery of every endpoint.
- Hidden parameter discovery may not identify all parameters.
- Vulnerability pattern classification identifies potentially interesting URLs, not confirmed vulnerabilities.
- Nuclei results may include false positives and require manual verification.
- Baseline comparison uses exact-line matching.
- A failed scan stage may result in incomplete output.

---

## Disclaimer

SuicideSquad is intended for authorized security testing, vulnerability assessment, and educational purposes only.

The user is responsible for obtaining appropriate authorization before scanning any system.

The author assumes no responsibility for misuse, unauthorized access, service disruption, or damage caused by this tool.

---

## License

Specify your license here.

For example:

```text
MIT License
```

---

**SuicideSquad - Automate your security reconnaissance and DAST workflow.**
