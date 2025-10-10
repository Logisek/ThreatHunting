## ThreatHunting - Windows Event Log Threat Hunting Toolkit

Windows-focused threat hunting utility to rapidly search Windows Event Logs for suspicious activity across key tactics like credential access, persistence, lateral movement, execution/defense evasion, exfiltration/C2, and smoking-gun indicators. It supports filters by time, log type, event level, source, and description, and can display results in JSON, CSV, text, or a compact matrix view. It also includes helpers to check log availability, review and configure retention, and open Event Viewer or the log directory.

**Important Note**: In enterprise environments, it is recommended to centralize logs in a SIEM and operate within a SOC workflow for alerting, enrichment, and long-term retention. Use this tool for local triage, spot-checking, validation, and rapid investigation on endpoints.

### Key Features
- Search by curated event IDs grouped into hunting categories
- Filter by time window, level, log type, source, description, and rich regex field filters (user/process/parent/ip/port/logon-type) with AND/OR/NOT
- Output in JSON, JSONL (NDJSON), CSV, human-readable text, or matrix view; optional timeline output with sessionization
- Concurrency and progress bars for faster multi-log scanning; unlimited or capped events with --max-events
- Risk scoring for each event + triage summaries (Top findings, category/source heatmaps)
- Tamper and health checks (log clears, policy changes, service stops, time skew, large gaps)
- Sigma rule matching (load local YAML rules, tag matches, boost scores)
- IOC-driven hunting (ingest IPs/domains/hashes/substrings; tag matches; boost scores; per-IOC hit summary)
- Offline EVTX parsing (hunt across .evtx files/directories, preserve channel/timestamps)
- Config management: single/multiple configs, schema validation, merge diffs, and named presets
- Sinks and integrations: HTTP webhook and Splunk HEC
- Quick checks for log availability coverage and retention settings
- Configure retention (PowerShell, registry, or direct API)
- Open Event Viewer and Windows log directories
- UAC-aware admin check, optional auto-elevation, and warning suppression

---

## Installation and Requirements

- Windows 10/11 or Windows Server with Event Logs enabled
- Python 3.8+
- Dependencies:
  - `pywin32` (Windows Event Log + Win32 APIs)
  - `tqdm` (optional, for progress bars)
  - `requests` (optional, for webhook and Splunk HEC sinks)
  - `colorama` (optional, for colorized text output)

Quick install:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install pywin32 tqdm requests colorama PyYAML python-evtx
```

Run from project directory:

```bash
python ThreatHunting.py -h
```

Admin privileges are recommended for full functionality (especially the `Security` log and retention configuration). You can auto-elevate or suppress warnings via flags; see below.

---

## Event Categories and Defaults

The tool ships with curated default categories and event IDs. You can also load your own via `--config` with a JSON file following the same structure (see files under `config/` like `config/common_events.json`, `config/advanced_events.json`, `config/simple_privilege.json`, `config/privilege_escalation.json`, `config/accessible_events.json`, `config/test_events.json`, `config/custom_events.json`).

When no `--config` is provided, built-in defaults are used. The tool prints how many unique Event IDs and categories are loaded on start.

List categories without running a search:

```bash
python ThreatHunting.py --list-categories
```

### Config folder structure and making your own

All shipped configurations live under `config/`. You can create additional JSON files there and point the tool to them with `--config config/your_file.json`.

Contents of a config JSON:

```json
{
  "category_name": [4688, 4698, 7045],
  "another_category": [4624, 1102]
}
```

Guidance for custom configs:
- Keep categories purpose-driven (e.g., "ransomware_initial", "persistence_services").
- Favor smaller, high-signal sets for speed; add broader sets during deeper IR.
- Reuse/extend `config/custom_events.json` as a template.
- Test by listing categories: `python ThreatHunting.py --config config/your_file.json --list-categories`.

### Event JSON Files (config/)

All bundled configuration files live in the `config/` folder. These JSON files define named categories mapped to lists of Event IDs. You can pass any of them to `--config <path>` (e.g., `--config config/event_ids.json`) to use those categories during a hunt. The schema is:

```json
{
  "category_name": [
    4688,
    4698,
    7045
  ],
  "another_category": [
    4624,
    1102
  ]
}
```

- `config/event_ids.json`: Balanced, production-ready default categories used by the tool when no config is supplied. Covers credential access, persistence, lateral movement, execution/evasion, exfiltration/C2, smoking-gun indicators, and correlation helpers.
- `config/accessible_events.json`: Practical set emphasizing commonly accessible Application/System/Security events for broad hunting when access is limited.
- `config/advanced_events.json`: Enriched categories for more advanced scenarios, including a `sysmon_events` set (1–25) if Sysmon is deployed.
- `config/common_events.json`: Baseline common Application/System event IDs to understand general system/app stability and context during triage.
- `config/privilege_escalation.json`: Very broad Security event catalog focused on privilege escalation and related Security IDs. Useful for exhaustive reviews, can be noisy.
- `config/simple_privilege.json`: Concise privilege-escalation-centric set; lighter-weight than the full `privilege_escalation.json` list.
- `config/test_events.json`: Large synthetic set for testing and stress validation. Not recommended for routine hunts.
- `config/custom_events.json`: Example file showing how to define your own categories (e.g., `my_custom_category`, `high_priority_events`, `powershell_events`). Use this as a starting template.

New curated configs included:
- `config/sysmon_core.json`: Core Sysmon events (process create, network, image loads, file create, registry, WMI, drivers, code injection, named pipes, DNS) for environments with Sysmon deployed.
- `config/powershell_deep.json`: PowerShell Operational and Script Block Logging focus (4100/4103/4104 plus common operational IDs), useful for script-based attacks.
- `config/rdp_remote_access.json`: RDP and remote session telemetry (logon/logoff, session reconnect/disconnect, and TerminalServices events like 1149). Helps trace interactive remote access.
- `config/kerberos_anomalies.json`: Kerberos requests and failures that often indicate brute force, service ticket abuse, or misconfigurations (4768/4769/4771/4772/4773/4776, etc.).
- `config/persistence_autoruns.json`: Autoruns and service/task creation/modification (registry run keys 12/13/14, tasks 106/140/4698, services 7040/7045, and installer 4697).
- `config/network_wfp_anomalies.json`: Windows Filtering Platform allow/deny and related events (5152/5153/5156/5157/5158/5159/5160/5161) to spot suspicious network patterns.

When to use which:
- Quick incident triage on a workstation: `event_ids.json` or `accessible_events.json`.
- Deep-dive security review: `privilege_escalation.json` (expect volume) or `advanced_events.json` (if Sysmon present).
- Environment-specific hunts: start from `custom_events.json` and tailor categories/events.

---

## Artifact directories: IoC, STIX, EVTX, and Sigma

This repository includes directories with ready-to-use hunting assets:

- `sigma/`:
  - Location for Sigma-style rules. We include starter rules under `sigma/windows/` (e.g., `process_creation.yml`, `log_cleared.yml`, `service_installed.yml`).
  - Use with `--sigma-dir sigma/windows` to tag events locally and boost scores.

- `ioc/`:
  - IOC samples for quick testing and demos.
  - `ioc/common_iocs.csv` (CSV headers: `type,value`) supports `ip`, `domain`, `hash`, `substring`.
  - `ioc/common_iocs.txt` simple line-based list; auto-detected type.
  - `ioc/stix/common_stix.json` minimal STIX bundle with indicators.
  - Use with `--ioc` and `--ioc-format {csv,txt,stix}`.

- `evtx/`:
  - Place sample `.evtx` files here (see `evtx/README.txt`) for offline hunting.
  - Use with `--evtx evtx` to scan the entire directory recursively.

Quick commands:

```bash
# Sigma local matching
python ThreatHunting.py --hours 48 --all-events --sigma-dir sigma/windows --format text --matrix

# IOC CSV ingestion
python ThreatHunting.py --hours 24 --all-events --ioc ioc/common_iocs.csv --ioc-format csv --format json

# STIX JSON ingestion
python ThreatHunting.py --hours 24 --all-events --ioc ioc/stix/common_stix.json --ioc-format stix --format jsonl

# Offline EVTX hunting (directory)
python ThreatHunting.py --hours 168 --evtx evtx --all-events --format text --matrix
```

---

## Argument Reference

- `--hours <int>`: Time window to search backward from now (default: 24).
- `--format {json,text,csv}`: Output format (default: text).
- `--format {json,jsonl,text,csv}`: Output format (default: text). `jsonl` prints one JSON object per line.
- `--categories <list>`: Limit search to one or more category names.
- `--list-categories`: List available categories and exit.
- `--check-availability`: Show how far back each log retains data and summary.
- `--show-retention`: Print current retention settings for core logs.
- `--configure-retention <DAYS>`: Configure log retention (admin required).
  - `--max-size <MB>`: Max log size in MB (default: 1024).
  - `--retention-policy {overwrite_as_needed,archive_when_full,never_overwrite}`: Retention mode (default: overwrite_as_needed).
  - `--method {registry,powershell,auto}`: How to configure (default: auto; tries PowerShell then registry, then direct API).
  - `--force`: Attempt configuration even if admin is not detected (may still fail).
- `--open-event-viewer`: Launch Event Viewer (`eventvwr.msc`).
- `--open-log-directory`: Open the Windows Event Log directory in Explorer.
- `--open-both`: Open both Event Viewer and the log directory.
- `--config <path>`: Load event IDs/categories from a JSON file.
- `--configs <list>`: Provide multiple config files to merge (later files override earlier). Prints diffs of added categories/IDs.
- `--preset <name>`: Use a named preset from `config/` (accessible, advanced, common, privilege, simple_privilege, event_ids, custom).
- `--event-ids <list>`: Explicit Event IDs to search (e.g., `--event-ids 1066 7045 4688`). Overrides categories (unless `--all-events`).
- `-o, --output <path>`: Write results to a UTF‑8 file. For matrix view, format is treated as text.
- `--level {Error,Warning,Information,Critical,Verbose}`: Filter by event level.
- `--level-all {Error,Warning,Information,Critical,Verbose}`: Return all events of a level (ignores event ID filter).
- `--levels-all <list>`: Return all events of multiple levels (e.g., `--levels-all Warning Error`).
- `--matrix`: Tabular, width-limited matrix for quick console triage (text view).
- `--log-filter {Application,Security,Setup,System}`: Restrict search to a single log.
- `--source-filter <string>`: Case-insensitive contains-match on event source.
- `--description-filter <string>`: Case-insensitive contains-match on event description.
- `--all-events`: Search ALL events, ignoring Event IDs/categories and level filters. Combine with rich filters.
- `--max-events <int>`: Maximum events to check per log (0 = unlimited). Replaces the older ~1000 internal cap.
- `--concurrency <int>`: Number of logs to process in parallel.
- `--progress`: Show per-log progress bars with ETA (requires `tqdm`).
- `--check-service`: Check Windows Event Log service status and exit.
- `--allowlist <path>`: JSON file listing known/expected activity to suppress.
- `--suppress <rules>`: Ad-hoc suppression rules (e.g., `source:Security-SPP eid:4688 user:ACME\\alice`).
- `--webhook <url>`: POST results to an HTTP endpoint (JSONL for `--format jsonl`, otherwise JSON batches).
- `--hec-url <url>` and `--hec-token <token>`: Send results to Splunk HEC.
- `--sink-batch <int>`: Batch size for sink posts.
- `--ioc <path>`: IOC file path (CSV/TXT/STIX). CSV must have headers `type,value`.
- `--ioc-format {csv,txt,stix}`: IOC input format (default csv).
- `--ioc-boost <int>`: Score boost per IOC hit (default 5).
- `--evtx <paths>`: One or more .evtx files or directories (recursive) to parse offline.
- `--sigma-dir <path>`: Directory with Sigma YAML rules to evaluate locally (simple selection support).
- `--sigma-boost <int>`: Score boost per matched Sigma rule (default 10).

Scoring and triage output:
- Every result includes `score` (0–100) and `risk_reasons` in JSON; text/matrix/CSV include `score`.
- After results, a triage summary prints Top findings (by score) and counts by category/source.

Rich field filters (regex-capable) and boolean logic:
- `--user-filter <regex>`: Match on resolved user (from event SID when available), e.g., `ACME\\alice` or `^svc_`.
- `--process-filter <regex>`: Match on process/image name or path, e.g., `powershell\.exe|cmd\.exe`.
- `--parent-filter <regex>`: Match on parent image, e.g., `explorer\.exe|services\.exe`.
- `--ip-filter <regex>`: Match on source IP address, e.g., `^10\.|192\.168\.`.
- `--port-filter <regex>`: Match on source port, e.g., `^(443|8080)$`.
- `--logon-type-filter <regex>`: Match on Logon Type (e.g., `^10$` for RDP).
- `--bool {and,or}`: Combine filters with AND (default) or OR.
- `--not`: Negate the combined result (NOT).

Timeline export and sessionization:
- `--timeline {jsonl,csv}`: Output a chronological timeline in JSON Lines (one JSON object per line) or CSV format.
- `--sessionize {none,user,host,logon,log}`: Add a derived `session` key to each event and optionally group by user (from event SID), host, logon ID (parsed from description), or log.

Elevation and warnings:
- `--no-admin-warning`: Suppress the non-elevated warning.
- `--elevate`: If not elevated, re-launch the process with Administrator privileges via UAC.

---

## Quick-Start Threat Hunting Playbooks

Below are concise playbooks for triaging a potentially compromised Windows workstation (assuming logs are intact). Run the console as Administrator if possible.

### 1) Broad suspicious activity sweep (last 24h)

```bash
python ThreatHunting.py --hours 24 --format text --matrix
```

Tips:
- Scan with `--categories critical_smoking_gun_indicators` to focus on high-signal events.
- Add `--level Warning` or `--level Error` to reduce noise.

### 2) Focus on credential access and privilege escalation

```bash
python ThreatHunting.py --hours 48 --categories credential_access_and_privilege_escalation --format json
```

Check for suspicious `4688` process creations, `4672` special privileges, group membership changes, and log clears (`1102`).

### 3) Persistence and startup modifications

```bash
python ThreatHunting.py --hours 72 --categories persistence_and_startup_modification --format text --matrix
```

Look for scheduled tasks (`4698`, Task Scheduler 106/140), services changes (`7040`, `7045`), and registry autoruns (12/13/14).

### 4) Lateral movement and remote access

```bash
python ThreatHunting.py --hours 24 --categories lateral_movement_and_remote_access --format text
```

Filter by description for known tools or hosts:

```bash
python ThreatHunting.py --hours 24 --categories lateral_movement_and_remote_access --description-filter "psexec"
```

### 5) Execution and defense evasion (PowerShell/WMI)

```bash
python ThreatHunting.py --hours 24 --categories execution_and_defense_evasion --format json
```

Add source/description filters for suspicious script blocks (`4104`) and module logs (`4103`).

### 6) Exfiltration and C2 indicators

```bash
python ThreatHunting.py --hours 48 --categories exfiltration_and_c2 --format text --matrix
```

Look for Windows Filtering Platform events (`5156`, `5157`) and tool-based transfers.

### 7) Full-level sweep ignoring event IDs (noise-tolerant)

```bash
python ThreatHunting.py --hours 12 --level-all Error --format json
```

Use this to quickly surface all errors in a time window, then pivot.

---

## Practical Investigation Tips

- Run as Administrator for best coverage; the `Security` log may be restricted otherwise. Use `--elevate` if needed.
- Start broad (matrix view) to spot patterns; then pivot with `--source-filter` and `--description-filter`.
- Save artifacts: `-o results.json` or `-o findings.csv` to preserve triage data.
- Validate log coverage first: `--check-availability` and `--show-retention`.
- Improve retention if allowed: `--configure-retention DAYS --method auto`.
- Confirm suspicious activity with multiple signals (e.g., process creation + new service + unusual outbound connection).
- Correlate local findings with centralized SIEM data when available.

---

## Usage Examples and Combinations

General:

```bash
# Default sweep, last 24h, text output
python ThreatHunting.py

# JSON output for downstream tooling
python ThreatHunting.py --format json --hours 6

# Matrix view for console triage
python ThreatHunting.py --matrix --hours 12
```

Category scoping:

```bash
# Single category
python ThreatHunting.py --categories critical_smoking_gun_indicators --hours 24

# Multiple categories
python ThreatHunting.py --categories credential_access_and_privilege_escalation execution_and_defense_evasion --hours 48 --format json
```

Log scoping:

```bash
# Only Security log (admin recommended)
python ThreatHunting.py --log-filter Security --hours 24 --format text

# Application log only
python ThreatHunting.py --log-filter Application --hours 24 --matrix
```

Level filtering:

```bash
# Only Warning-level events
python ThreatHunting.py --level Warning --hours 24

# Ignore event ID lists; show all Error events in window
python ThreatHunting.py --level-all Error --hours 24 --format json
```

Source/description filtering:

```bash
# Filter by source contains 'Service Control Manager'
python ThreatHunting.py --source-filter "Service Control Manager" --hours 24

# Filter description for known tool strings (example: OpenVPN)
python ThreatHunting.py --description-filter "OpenVPN" --hours 24 --format json

# Combine multiple filters
python ThreatHunting.py --log-filter System --level Warning --source-filter "Driver" --description-filter "failed"
```

Output to file:

```bash
# Save matrix (treated as text) to file
python ThreatHunting.py --matrix -o triage.txt

# Save JSON results safely to UTF-8 file
python ThreatHunting.py --format json -o results.json
```

Custom configuration:

```bash
# Load your own event set
python ThreatHunting.py --config config/custom_events.json --hours 72 --format text

# List categories and exit
python ThreatHunting.py --list-categories
```

Config-specific examples:

```bash
# Sysmon core (if Sysmon deployed)
python ThreatHunting.py --config config/sysmon_core.json --hours 24 --format json

# Deep PowerShell hunting
python ThreatHunting.py --config config/powershell_deep.json --hours 48 --description-filter "DownloadString"

# RDP/remote access focus
python ThreatHunting.py --config config/rdp_remote_access.json --hours 24 --matrix

# Kerberos anomaly hunting
python ThreatHunting.py --config config/kerberos_anomalies.json --hours 72 --format text

# Persistence and autoruns sweep
python ThreatHunting.py --config config/persistence_autoruns.json --hours 168 --matrix

# Network WFP anomalies
python ThreatHunting.py --config config/network_wfp_anomalies.json --hours 24 --format json

# Balanced defaults (used when no --config is provided)
python ThreatHunting.py --config config/event_ids.json --hours 24 --matrix

# Accessible set for common logs when access is limited
python ThreatHunting.py --config config/accessible_events.json --hours 24 --format text

# Advanced set (includes Sysmon category if deployed)
python ThreatHunting.py --config config/advanced_events.json --hours 48 --format json

# Common Application/System context during triage
python ThreatHunting.py --config config/common_events.json --hours 72 --matrix

# Focused privilege-escalation deep review (very verbose)
python ThreatHunting.py --config config/privilege_escalation.json --hours 168 --format text

# Lightweight privilege-escalation sweep
python ThreatHunting.py --config config/simple_privilege.json --hours 48 --matrix

# Large synthetic set for testing/stress validation
python ThreatHunting.py --config config/test_events.json --hours 2 --format json

# Your tailored categories (edit custom_events.json first)
python ThreatHunting.py --config custom_events.json --hours 72 --format text
```

Admin handling:

```bash
# Suppress non-elevated warning when permissible
python ThreatHunting.py --no-admin-warning --hours 12

# Auto re-launch elevated when needed (UAC prompt)
python ThreatHunting.py --elevate --hours 24 --categories critical_smoking_gun_indicators
```

Retention and coverage:

```bash
# Check how far back logs retain data per log
python ThreatHunting.py --check-availability

# Show current retention settings
python ThreatHunting.py --show-retention

# Configure retention for 365 days, auto method
python ThreatHunting.py --configure-retention 365 --max-size 2048 --retention-policy overwrite_as_needed --method auto

# Force attempt even if admin not detected (may still fail)
python ThreatHunting.py --configure-retention 365 --force
```

Composed examples:

```bash
# 1) Broad triage with matrix and output file
python ThreatHunting.py --hours 24 --matrix -o triage.txt

# 2) High-signal sweep + JSON export for SOC enrichment
python ThreatHunting.py --categories critical_smoking_gun_indicators --hours 48 --format json -o indicators.json

# 3) PowerShell/WMI evasion focus with description pivoting
python ThreatHunting.py --categories execution_and_defense_evasion --description-filter "script" --hours 24 --format text

# 4) Lateral movement focus, only Security log, errors only
python ThreatHunting.py --categories lateral_movement_and_remote_access --log-filter Security --level Error --hours 24 --format json

# 5) Custom event set, Application log, warnings in last 7 days
python ThreatHunting.py --config custom_events.json --log-filter Application --level Warning --hours 168 --matrix
```

### Timeline export and sessionization examples

```bash
# Simple JSONL timeline for last 12 hours
python ThreatHunting.py --hours 12 --timeline jsonl

# CSV timeline sessionized by user (derived from event SID when available)
python ThreatHunting.py --hours 24 --timeline csv --sessionize user > timeline.csv

# Focus on credential access/escalation and sessionize by Logon ID parsed from descriptions
python ThreatHunting.py --categories credential_access_and_privilege_escalation --hours 24 --timeline jsonl --sessionize logon

# Security log, all Error events, CSV timeline grouped by host
python ThreatHunting.py --log-filter Security --level-all Error --hours 24 --timeline csv --sessionize host > sec_errors_timeline.csv
```

### Rich field filters examples

```bash
# Hunt for PowerShell or CMD spawns, regardless of category
python ThreatHunting.py --hours 24 --process-filter "powershell\.exe|cmd\.exe" --format json

# RDP logons (Logon Type 10) from RFC1918 ranges, CSV output
python ThreatHunting.py --log-filter Security --hours 24 --logon-type-filter "^10$" --ip-filter "^(10\. |192\.168\. |172\.(1[6-9]|2[0-9]|3[0-1])\.)" --format csv

# Parent is explorer.exe and process is reg.exe, require both (AND)
python ThreatHunting.py --hours 24 --parent-filter "explorer\.exe" --process-filter "reg\.exe" --bool and --matrix

# Any events for service accounts (user starts with svc_), OR logic
python ThreatHunting.py --hours 48 --user-filter "^svc_" --process-filter "sc\.exe|services\.exe" --bool or --format json

# Exclude (NOT) cmd.exe/PowerShell spawns from timeline
python ThreatHunting.py --hours 12 --timeline jsonl --process-filter "powershell\.exe|cmd\.exe" --not
```

### Additional examples

```bash
# Search explicit Event IDs across all logs
python ThreatHunting.py --hours 48 --event-ids 1066 7045 4688 --format text --matrix

# Search ALL events but still filter by process name
python ThreatHunting.py --hours 48 --all-events --process-filter "explorer\.exe" --format text --matrix

# Search Application log General text for DLLs (General tab contains .dll paths)
python ThreatHunting.py --hours 300 --all-events --log-filter Application --description-filter ".dll" --format text --matrix

# Search Information and Warning levels, process match
python ThreatHunting.py --hours 48 --levels-all Information Warning --process-filter "svchost\.exe|explorer\.exe" --format text --matrix

# Security process creations (Information) with executable match
python ThreatHunting.py --hours 24 --log-filter Security --levels-all Information --process-filter "\\.exe" --format text --matrix

# Suppress known noisy sources and a specific Event ID
python ThreatHunting.py --hours 48 --all-events --suppress source:Security-SPP eid:1066 --format text --matrix

# Use an allowlist JSON to suppress expected jobs/services
python ThreatHunting.py --hours 168 --config config/event_ids.json --allowlist config/allowlist.json --format json

# Concurrency + progress with scoring in matrix (score column visible)
python ThreatHunting.py --hours 72 --all-events --max-events 0 --process-filter "powershell\\.exe|cmd\\.exe" --concurrency 4 --progress --format text --matrix

# Send JSONL to a webhook sink
python ThreatHunting.py --hours 24 --all-events --format jsonl --webhook https://example.org/hook

# Send to Splunk HEC
python ThreatHunting.py --hours 24 --event-ids 4688 4698 --format jsonl --hec-url https://splunk:8088/services/collector --hec-token YOUR_TOKEN

# Config management: start from a preset, then merge two custom layers
python ThreatHunting.py --preset event_ids --configs config/custom_events.json config/advanced_events.json --hours 48 --format text

# Config management: merge baseline + org overrides (no preset)
python ThreatHunting.py --configs config/baseline.json config/org_overrides.json --hours 72 --format json
```

### Performance and progress examples

```bash
# Unlimited scan with 4 workers and progress bars (requires tqdm)
python ThreatHunting.py --hours 72 --all-events --max-events 0 --process-filter "explorer\.exe" --concurrency 4 --progress --format text --matrix

# Cap at 50k per-log with levels and JSON output
python ThreatHunting.py --hours 168 --levels-all Information Warning --max-events 50000 --concurrency 4 --progress --format json
```

### Incident responder quick recipes

```bash
# Investigate a single user across all logs (matrix, last 48h)
python ThreatHunting.py --hours 48 --all-events --user-filter "^ACME\\alice$" --format text --matrix

# Per-user timeline (JSONL) and sessionize by user
python ThreatHunting.py --hours 24 --all-events --timeline jsonl --sessionize user > user_timeline.jsonl

# Kerberos anomalies with possible lateral movement source IPs
python ThreatHunting.py --hours 24 --event-ids 4768 4769 4771 4772 4773 4775 --ip-filter "^10\.10\." --format text

# Service persistence (7045) with suspicious parents (sc.exe/services.exe)
python ThreatHunting.py --hours 72 --event-ids 7045 --parent-filter "sc\.exe|services\.exe" --format text --matrix

# Scheduled task creation and modification (4698 + Task Scheduler 106/140)
python ThreatHunting.py --hours 72 --event-ids 4698 106 140 --format json

# PowerShell/WMI execution bursts, sessionized by host
python ThreatHunting.py --hours 12 --categories execution_and_defense_evasion --timeline csv --sessionize host > exec_bursts.csv

# All Information-level Security events mentioning LSASS in General text
python ThreatHunting.py --hours 24 --log-filter Security --levels-all Information --description-filter "lsass" --format text

# SMB share activity (staging/exfil) constrained to svc_ accounts
python ThreatHunting.py --hours 24 --event-ids 5140 5142 5145 --user-filter "^svc_" --format json

# RDP session tracking with RFC1918 IPs
python ThreatHunting.py --hours 48 --event-ids 21 24 25 1149 --ip-filter "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" --format text

# Ship JSONL for Security log errors with allowlist applied
python ThreatHunting.py --hours 24 --log-filter Security --levels-all Error --allowlist config/allowlist.json --format jsonl > security_errors.jsonl

# Sigma-driven triage: LOLBins + timeline by logon session
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --sigma-boost 10 --timeline jsonl --sessionize logon > sigma_sessions.jsonl

# High-volume scan with concurrency and noise suppression (source suppression)
python ThreatHunting.py --hours 168 --all-events --max-events 30000 --concurrency 4 --suppress source:Security-SPP --format text --matrix

# Focused lookback for log tamper signals
python ThreatHunting.py --hours 7 --event-ids 1102 1101 1100 4719 --format text

# Offline EVTX hunting across a directory of files (triage bundle)
python ThreatHunting.py --hours 168 --evtx C:\\triage\\evtx_dump --all-events --format text --matrix
```

### Sigma rules examples

```bash
# Load local Sigma rules folder and boost scores for matches
python ThreatHunting.py --hours 48 --all-events --sigma-dir sigma/windows --sigma-boost 15 --format text --matrix

# Combine Sigma with explicit Event IDs and ship matches via JSONL webhook
python ThreatHunting.py --hours 24 --event-ids 4688 7045 1102 --sigma-dir sigma/windows --format jsonl --webhook https://example.org/hook

# Use Sigma alongside allowlist suppression to reduce noise
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --allowlist config/allowlist.json --format json
```

### IOC-driven hunting examples

```bash
# CSV IOCs (type,value). Types: ip, domain, hash, substring
python ThreatHunting.py --hours 24 --all-events --ioc iocs.csv --ioc-format csv --format text --matrix

# TXT list (mixed IOCs). Each line one indicator; auto-detected as ip/domain/hash/substring
python ThreatHunting.py --hours 48 --all-events --ioc iocs.txt --ioc-format txt --format json

# STIX JSON indicators (naive extraction from pattern/name)
python ThreatHunting.py --hours 24 --all-events --ioc stix.json --ioc-format stix --format jsonl

# IOC hunt combined with Sigma and allowlist for reduced noise
python ThreatHunting.py --hours 24 --all-events --ioc iocs.csv --ioc-format csv --sigma-dir sigma/windows --allowlist config/allowlist.json --format text --matrix
```

### Sigma rules (authoring and organization)

Folder layout:

```
sigma/
  windows/
    process_creation.yml
    log_cleared.yml
    service_installed.yml
```

Supported fields in selections (simple local matcher):
- `EventID` or `event_id` (integer equality)
- `description|contains`, `process|contains`, `source|contains`, `user|contains` (case-insensitive substring)
- Plain field equality for simple keys (e.g., `log_name: Security`)

Detection block must use a single selection with `condition: selection`.
Example rule (detect LOLBins at process creation):

```yaml
title: Suspicious LOLBin Process Creation
id: win_proc_lolbin_001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    process|contains: powershell.exe
  condition: selection
tags:
  - attack.execution
  - attack.t1059
```

Notes and limits:
- This is a lightweight evaluator for quick local tagging, not a full Sigma engine.
- If you need richer matching (wildcards, multiple selections, 1 of N, etc.), consider pre-compiling rules externally and piping JSONL into the tool or contributing extended logic.

Additional Sigma usage examples:

```bash
# Only tag (no score change): set boost to 0 to avoid inflating scores
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --sigma-boost 0 --format text --matrix

# Sigma + timeline to sequence matched activity
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --timeline jsonl --sessionize user

# Ship only Sigma-matched events by filtering at sink (JSONL with webhook); use allowlist to reduce noise
python ThreatHunting.py --hours 12 --all-events --sigma-dir sigma/windows --format jsonl --webhook https://example.org/hook --allowlist config/allowlist.json

# Combine Sigma with multi-level search and process filter
python ThreatHunting.py --hours 48 --levels-all Information Warning --process-filter "rundll32\.exe|regsvr32\.exe" --sigma-dir sigma/windows --format text --matrix
```

---

## Troubleshooting

- No results found: Expand time window with `--hours`, or switch to `--level-all` to validate logging volume.
- Access denied on `Security` log: Run elevated (or use `--elevate`). Some policies may still restrict access even when elevated.
- Output redirection issues: Use `-o` to write directly to file with UTF‑8 handling.
- Retention configuration fails: Verify elevation and try `--method powershell` or `--method registry`. Some environments enforce policies that override local settings.

---

## License

See `LICENSE` in this repository.

---

## Event ID Reference Matrix

Below is a practical reference for the unique event IDs used across the included JSON configs. Where the repository references very large ranges (e.g., hundreds of Security audit IDs), they are grouped for readability. Prefer the Microsoft official documentation for authoritative, version-specific semantics.

### Windows Security Log - Authentication and Logon

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 4624 | An account was successfully logged on | Baseline logons, pivot by LogonType for network/RDP/service logons, lateral movement |
| 4625 | An account failed to log on | Password spraying/brute force indicators, failed lateral movement |
| 4634 | An account was logged off | Session lifecycle correlation with 4624/4648 |
| 4648 | A logon was attempted using explicit credentials | Pass-the-Hash/Ticket usage, remote exec tools (PsExec/WMI) |
| 4672 | Special privileges assigned to new logon | Admin-equivalent context; privilege escalation and high-value sessions |
| 4673–4674 | Sensitive privilege use / Privileged service called | Detection of privilege API usage by processes |
| 4697 | A service was installed in the system | Persistence, privilege escalation, remote service creation |
| 4698 | A scheduled task was created | Persistence, living-off-the-land tasking |
| 4732/4728/4756 | Member added to local/global/universal group | Privilege escalation via group membership changes |
| 4768/4769/4771 | Kerberos TGT/TGS request/failure | Kerberoasting, clock skew, KDC issues, brute forcing |
| 4772/4773/4774/4775 | Kerberos auth anomalies | Ticket renewals/failures, policy issues, potential abuse |
| 4776 | NTLM authentication | Legacy auth, relay risk, brute force indicators |
| 1102 | The audit log was cleared | High-signal defense evasion |

### Windows System/Application - Services, Tasks, Registry, Shares

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 7040 | Service start type changed | Persistence via autorun service changes |
| 7045 | A service was installed (System) | Persistence/remote execution, tool staging |
| 106/140 (Task Scheduler) | Task created/updated | Persistence and scheduled execution |
| 12/13/14 (Registry) | Registry value/key added/modified | Autoruns, tampering with security controls |
| 4688 | Process creation | Parent-child anomalies, LOLBins, malware invocations |
| 4689 | Process termination | Correlate lifetimes, short-lived suspicious processes |
| 5140/5142/5145 | SMB share accessed/created/object checked | Lateral movement, data staging/exfil over SMB |
| 4778/4779 | Session reconnect/disconnect | RDP/interactive session tracking |

### PowerShell and Script Execution

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 4100 | PowerShell engine lifecycle | Baseline session/activity presence |
| 4103 | PowerShell module logging | Cmdlet/module usage; detect living-off-the-land |
| 4104 | PowerShell script block logging | High-signal malicious script content (obfuscation, download cradle) |
| 53504/53506/53507 | PowerShell operational (newer channels) | Deep telemetry for script operations (if enabled) |

### Windows Filtering Platform (Network)

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 5152/5153 | Packet blocked by filter | Host-based firewall blocks; scanning, failed C2 |
| 5156 | Connection allowed | Baseline outbound/inbound; unusual destinations/ports |
| 5157 | Connection blocked | Egress control efficacy; policy tamper attempts |
| 5158/5159/5160/5161 | Resource assignments and state | Low-level flow diagnostics; advanced network hunting |

### Windows Defender (Microsoft Defender AV)

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 1116 | Malware detected | Direct detection signal; pivot to related process/file |
| 1117 | Remediation action taken | Cleanup actions; verify success and residual indicators |

### RDP and Remote Access (Terminal Services)

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 1149 | Successful RDP logon (TS-Gateway/TermServ) | Trace interactive access, brute force success |
| 21/24/25 | Session connect/disconnect/reconnect | Account usage patterns, suspicious timing |

### Sysmon (if deployed)

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 1 | Process creation | Parent-child chains, command-lines, LOLBins |
| 2 | File creation time changed | Timestomping detection |
| 3 | Network connection | Outbound C2, lateral movement, rare destinations |
| 4 | Sysmon service state changed | Tamper and defense evasion |
| 5 | Process terminated | Lifecycle correlation with Event ID 1 |
| 6 | Driver loaded | Kernel-mode implants, unsigned drivers |
| 7 | Image loaded | Malicious DLLs, injection indicators |
| 8 | CreateRemoteThread | Code injection between processes |
| 9 | Raw disk access | Ransomware behavior, low-level tampering |
| 10 | Process access (e.g., lsass.exe) | Credential theft tooling (Mimikatz, etc.) |
| 11 | File created | Payload drops, staging |
| 12/13/14 | Registry add/delete/set | Autoruns and tampering |
| 15 | File stream created | ADS usage for stealth |
| 16 | Sysmon configuration change | Tamper and logging gaps |
| 17/18 | Pipe created/connected | Lateral tools, inter-process comms |
| 19/20/21/22/23/24/25 | WMI event activity | Remote exec, persistence via WMI |

### Other and Category Placeholders

| Event ID | What it is | Why hunt for it |
|---|---|---|
| 400/403/600 | Provider-specific placeholders used in configs | Treat as hints to inspect provider channels relevant to execution/remoting |
| 1000–1050 (Application) | Common application crash/errors | Unusual instability tied to attack tooling |
| 6005/6006/6008/6009 (System) | Event log service start/stop; unexpected shutdown; OS version | Establish uptime and suspicious reboots |
| 6011–6050 (System) | System telemetry sequence | Operational context; correlate with attack timelines |
| 4673–5000 (Security, broad range) | Detailed privilege/use-of-rights and audit events | Exhaustive reviews during deep IR; pivot selectively by activity

