## ThreatHunting - Windows Event Log Threat Hunting Toolkit

Windows-focused threat hunting utility to rapidly search Windows Event Logs for suspicious activity across key tactics like credential access, persistence, lateral movement, execution/defense evasion, exfiltration/C2, and smoking-gun indicators. It supports filters by time, log type, event level, source, and description, and can display results in JSON, CSV, text, or a compact matrix view. It also includes helpers to check log availability, review and configure retention, and open Event Viewer or the log directory.

**Important Note**: In enterprise environments, it is recommended to centralize logs in a SIEM and operate within a SOC workflow for alerting, enrichment, and long-term retention. Use this tool for local triage, spot-checking, validation, and rapid investigation on endpoints.

### Key Features

- **Automated Compromise Assessment** (`--compromised`): Advanced threat detection with event correlation chains, hunt queries, high-confidence indicators, and compromise likelihood scoring
- **Process-Level Visibility**: Track process names and paths across all event outputs (console, CSV, JSON, file exports)
- **Flexible Date Filtering**: Search specific dates (`--date`) or time windows (`--hours`), exclude dates from analysis (`--exclude-date`)
- **Strict Time-Window Scoping**: All compromise summaries (chains, hunt matches, high-confidence, high-risk) honor the selected `--date`, `--from-date/--to-date`, or `--hours` window
- **Noise‑Resilient Scoring**: De-duplication, per-EventID score caps, temporal coherence weighting, and chain-aware capping to reduce false positives
- **Safe, Lean Exports**: Export is strictly date-scoped and de-duplicated with markers; regular stdout export is disabled while `--compromised` is active to avoid conflicts
- Search by curated event IDs grouped into hunting categories
- Filter by time window, level, log type, source, description, and rich regex field filters (user/process/parent/ip/port/logon-type) with AND/OR/NOT
- Output in JSON, JSONL (NDJSON), CSV, human-readable text, or matrix view; optional timeline output with sessionization
- Concurrency and progress bars for faster multi-log scanning; unlimited or capped events with --max-events
- Risk scoring for each event + triage summaries (Top findings with process info, category/source heatmaps)
- Tamper and health checks (log clears, policy changes, service stops, time skew, large gaps)
- Sigma rule matching (load local YAML rules, tag matches, boost scores)
- IOC-driven hunting (ingest IPs/domains/hashes/substrings; tag matches; boost scores; per-IOC hit summary)
- LOLBAS integration (auto-download latest LOLBins catalog and generate IOCs for hunting)
- Multi-host/remote collection (query remote hosts via WinRM/WMI/SSH with parallel collection and timeouts)
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
  "category_name": [4688, 4698, 7045],
  "another_category": [4624, 1102]
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
- **`config/compromise.json`**: Advanced compromise assessment configuration with event correlation chains, hunt queries, and high-confidence indicators for automated threat detection and scoring. Use with `--compromised` flag for comprehensive host compromise analysis.

When to use which:

- Quick incident triage on a workstation: `event_ids.json` or `accessible_events.json`.
- Deep-dive security review: `privilege_escalation.json` (expect volume) or `advanced_events.json` (if Sysmon present).
- Environment-specific hunts: start from `custom_events.json` and tailor categories/events.
- **Automated compromise assessment**: Use `--compromised` flag with `compromise.json` for guided threat hunting with correlation and scoring.

---

## Compromise Hunting and Assessment (`--compromised`)

The `--compromised` flag enables advanced, automated compromise assessment using the `config/compromise.json` configuration file. This mode goes beyond simple event ID matching by:

- **Event Correlation**: Chains multiple related events (e.g., failed logon → successful logon → process creation → service installation) to detect attack patterns
- **Hunt Queries**: Pre-defined queries targeting specific attack techniques (log tampering, PowerShell execution, persistence mechanisms)
- **High-Confidence Indicators**: Prioritizes events with strong malicious signals (log clearing, service installations, account manipulation)
- **Advanced Scoring Methodology**: Sophisticated multi-factor scoring system with event severity levels, context-aware multipliers, temporal weighting, and LOLBin detection
- **Compromise Likelihood Scoring**: Calculates a percentage score indicating the probability of host compromise based on findings
- **Interactive Config Selection**: Prompts user to include additional config files (privilege escalation, persistence, PowerShell, etc.) for expanded hunting scope
- **Detailed Analysis Report**: Provides comprehensive console output with attack chains, critical events, and category breakdowns
- **Scoring Transparency**: Optional `--scoring-breakdown` flag shows detailed scoring methodology and event classification

### compromise.json Structure

The `compromise.json` file includes several key sections:

```json
{
  "authentication_events": [4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776],
  "compromise_indicators": [1102, 4719, 7045, 4697, 4698, 4104, ...],
  "prioritize_high_confidence_indicators": [1102, 4104, 4697, 4720, 4728, ...],
  "correlate_event_chains": [
    {
      "name": "RDP/Lateral movement leading to service persistence",
      "steps": [
        {"event_id": 4625, "note": "Repeated failed logons", "source": "Security"},
        {"event_id": 4624, "note": "Successful logon", "source": "Security"},
        {"event_id": 4688, "note": "Suspicious process creation", "source": "Security"},
        {"event_id": 4697, "note": "Service installed", "source": "Security"}
      ]
    }
  ],
  "hunt_queries": [
    {
      "name": "Log tampering & audit policy change",
      "event_ids": [1102, 1100, 1104, 4719],
      "query_examples": {
        "splunk": "index=wineventlog (EventCode=1102 OR ...)",
        "elastic": "winlog.event_id: (1102 or 1100 or ...)"
      }
    }
  ]
}
```

### Advanced Scoring Methodology

The compromise likelihood calculation uses a sophisticated multi-factor scoring system with **very conservative chain-centric weighting**:

#### **Component Weighting (Very Conservative Approach)**
- **Event Chains**: **2.0x multiplier** - Correlated attack chains are weighted higher
- **Pattern Bonuses**: **1.3x multiplier** - Detected attack patterns (Kerberoasting, brute-force, etc.)
- **Individual Events**: **1.0x multiplier** - Base weight for standalone events
- **Hunt Queries**: **0.2x multiplier** - Heavily reduced to minimize noise

> **Why Chains Matter**: Event chains (e.g., 4625 → 4624 → 4672 → 7045) represent a complete attack sequence and are far more reliable indicators of compromise than isolated events. The 2.0x multiplier ensures that chain detection influences the likelihood score while minimizing false positives.

#### **Chain-Based Likelihood Thresholds (Very Conservative)**
- **5+ Chains Detected**: Minimum **65%** likelihood (high risk)
- **4 Chains Detected**: Minimum **55%** likelihood (moderate-high risk)
- **3 Chains Detected**: Minimum **45%** likelihood (moderate risk)
- **2 Chains Detected**: Minimum **35%** likelihood (low-moderate risk)
- **1 Chain Detected**: Minimum **25%** likelihood (low risk)
- **No Chains Detected**: Maximum **25%** likelihood (reduces false positives)

#### **Temporal Coherence Requirements (Critical)**
Attack chains require **temporal proximity** to be considered valid:
- **Maximum Chain Duration**: 60 minutes (events must occur within 1 hour)
- **Maximum Step Gap**: 30 minutes (max time between consecutive events)
- **Rapid Execution Bonus**: +15% confidence if chain completes in <10 minutes
- **Quick Execution Bonus**: +8% confidence if chain completes in <30 minutes

> **Why Temporal Coherence Matters**: A failed logon at 9 AM and another at 5 PM is likely legitimate (typos), not a brute-force attack. True attack chains show temporal clustering - events occur in rapid succession, not randomly scattered throughout the day.

#### **Event Severity Levels**
- **CRITICAL (20-25 pts)**: Log clearing, privilege escalation, group membership changes
- **HIGH (12-18 pts)**: Service installation, account creation, Kerberos failures  
- **MEDIUM (6-10 pts)**: Failed logons, Kerberos requests, PowerShell events
- **LOW (2-5 pts)**: Baseline process creation, DNS queries

#### **Context-Aware Multipliers**
- **LOLBin Execution**: 3x multiplier for any LOLBin from `lolbins_iocs.csv`
- **Privileged Execution**: 2x multiplier for admin/system/privileged contexts
- **Suspicious Processes**: 1.5x multiplier for cmd.exe, powershell.exe, etc.
- **Service Persistence**: 2.5x multiplier for suspicious service names
- **Task Persistence**: 1.8x multiplier for suspicious scheduled tasks
- **DNS Query Reduction**: 0.1x multiplier for common DNS queries (prevents false positives)

#### **Temporal Scoring**
- **Last Hour**: 2.0x multiplier
- **Last 6 Hours**: 1.5x multiplier  
- **Last 24 Hours**: 1.2x multiplier
- **Last 3 Days**: 1.0x multiplier
- **Older**: 0.8x multiplier

#### **Score Capping and Normalization**
- **DNS Query Capping**: Limited to 10 points total contribution regardless of quantity
- **Logarithmic Scaling**: Prevents always hitting 100% for realistic assessments
- **High Confidence Threshold**: Minimum 8% if high-confidence events found (without chains)

#### False-Positive Reduction (v1.2)
- **Universal De-duplication**: Events are deduplicated **before all analysis stages** (chain detection, likelihood scoring, console summaries, file export) using `(date, event_id, log_name, computer, description_hash)` to prevent duplicate noise from inflating scores and counts
- **Consistent Metrics**: Console summaries, file export counts, and likelihood scores all operate on the same deduplicated dataset, ensuring complete consistency
- **Per-EventID Caps**: Each Event ID's cumulative contribution is capped to avoid noisy categories overwhelming the score
- **Temporal Coherence**: Clustered indicators in short windows increase likelihood; spread-out events decrease it
- **Chain Requirement Cap**: If no attack chains detected, overall likelihood is capped (to reduce single-signal false positives)
- **Strict High-Confidence Set**: Only a curated subset of Event IDs contributes to the high-confidence bonus

### Usage Examples

**Basic Compromise Assessment (24 hours):**
```bash
python ThreatHunting.py --compromised --hours 24
```

**Interactive Config Selection:**
```bash
python ThreatHunting.py --compromised --date 2025-10-16
# Will prompt: "Include other config files? [Y/N] (default: N):"
```

**With Detailed Scoring Breakdown:**
```bash
python ThreatHunting.py --compromised --date 2025-10-16 --scoring-breakdown
```

**Time-Window Scoping (Single Day):**
```bash
# Summaries and exports include ONLY 2025-10-17
python ThreatHunting.py --compromised --date 2025-10-17 --export-events -o day_2025-10-17.txt
```

**Time-Window Scoping (Date Range):**
```bash
# Summaries and exports include ONLY events from 2025-10-15 through 2025-10-17
python ThreatHunting.py --compromised --from-date 2025-10-15 --to-date 2025-10-17 --export-events -o range_15_17.txt
```

**Verify Export Consistency:**
```bash
# Console and file will show identical deduplicated counts
python ThreatHunting.py --compromised --date 2025-10-17 --export-events -o test.txt

# Console might show:
#   Total Events Found: 277
#   Event ID 4697: 25 occurrences
#   Event ID 1100: 1 occurrence
#   Compromise Likelihood: 23.5%

# File will contain exactly 277 events (25× Event 4697, 1× Event 1100)
# Likelihood calculated from these 277 unique events only

# Before v1.3 deduplication fix:
#   Console: 16,208 events (with duplicates)
#   File: 277 events (deduplicated)
#   Likelihood: 37.9% (inflated by duplicates) ❌

# After v1.3 deduplication fix:
#   Console: 277 events (deduplicated)
#   File: 277 events (deduplicated)
#   Likelihood: 23.5% (accurate) ✅
```

**Hours Window (last 6 hours):**
```bash
# Summaries and exports scoped to now-6h..now
python ThreatHunting.py --compromised --hours 6 --export-events -o last6h.txt
```

**Extended Time Range (7 days):**
```bash
python ThreatHunting.py --compromised --hours 168
```

**Export Full Event Details to File:**
```bash
python ThreatHunting.py --compromised --hours 48 --export-events -o compromise_report.txt
```

**Exclude Specific Dates from Analysis:**
```bash
python ThreatHunting.py --compromised --hours 72 --exclude-date 2025-10-20 --exclude-date 2025-10-21
```

**Combined with Custom Time Range and Export:**
```bash
python ThreatHunting.py --compromised --hours 168 --exclude-date 2025-12-25 --export-events -o weekly_assessment.txt
```

### Output Analysis

The compromise assessment provides a concise console output with summaries, while detailed event lists are available through the `--export-events` option.

#### Console Output (Summaries)

1. **DETECTED ATTACK CHAINS**: Count and summary of correlated event sequences
   ```
   DETECTED ATTACK CHAINS (2 found):
     1. RDP/Lateral movement leading to service persistence (Confidence: 75%, 5 steps)
     2. Privilege escalation via scheduled task (Confidence: 60%, 3 steps)
   ```

2. **HUNT QUERY MATCHES**: Count of matched hunting queries
   ```
   HUNT QUERY MATCHES (3 queries matched):
     - Log tampering & audit policy change: 5 event(s)
     - Suspicious PowerShell execution: 48 event(s)
     - Service-based persistence: 12 event(s)
   ```

3. **HIGH-CONFIDENCE INDICATORS**: Count of high-confidence compromise indicators grouped by Event ID
   ```
   HIGH-CONFIDENCE INDICATORS (48 found):
     - Event ID 1102: 3 occurrence(s)
     - Event ID 4697: 8 occurrence(s)
     - Event ID 4720: 2 occurrence(s)
     ... and 5 more event types
   ```

4. **CRITICAL HIGH-RISK EVENTS**: Count of high-risk events grouped by Event ID
   ```
   CRITICAL HIGH-RISK EVENTS (15 found):
     - Event ID 1102: 3 occurrence(s)
     - Event ID 4720: 5 occurrence(s)
     - Event ID 4697: 7 occurrence(s)
   ```

5. **EVENT CATEGORY BREAKDOWN**: Distribution of findings across categories
   ```
   EVENT CATEGORY BREAKDOWN:
     - prioritize_high_confidence_indicators: 48 event(s)
     - authentication_events: 156 event(s)
     - service_events: 12 event(s)
   ```

6. **COMPROMISE LIKELIHOOD SCORE**: Overall assessment percentage
   ```
   [!] HIGH RISK: 85.3% - Strong indicators of compromise detected!
   [!] MEDIUM RISK: 55.2% - Some indicators of compromise detected
   [OK] LOW RISK: 12.1% - No significant indicators detected
   ```

7. **SCORING BREAKDOWN** (with `--scoring-breakdown` flag):
   ```
   SCORING BREAKDOWN:
   ==================================================
   Event Severity Distribution:
     Critical (20+ pts): 2 events
     High (12-19 pts): 8 events
     Medium (6-11 pts): 15 events
     Low (2-5 pts): 240 events
   
   Context Analysis:
     LOLBin executions: 3
     Privileged executions: 5
     Suspicious processes: 12
   
   Attack Chains: 1 detected
     Chain 1: RDP/Lateral movement leading to service persistence (confidence: 75.0%)
       - Contains LOLBin execution
       - Contains privileged execution
   
   Final Likelihood: 56.6%
   ==================================================
   ```

#### File Export (Detailed Events with Markers)

When using `--export-events` with `-o`, all discovered events are written to a file with complete details and markers indicating their significance:

**Marker Legend:**
- `[HIGH-CONFIDENCE]` = High-confidence compromise indicator
- `[HIGH-RISK]` = Critical high-risk event
- `[ATTACK-CHAIN]` = Part of detected attack chain
- `[HUNT-QUERY]` = Matched hunt query

**Example Export:**
```
ALL DISCOVERED EVENTS (156 total):
================================================================================
Markers:
  [HIGH-CONFIDENCE] = High-confidence compromise indicator
  [HIGH-RISK] = Critical high-risk event
  [ATTACK-CHAIN] = Part of detected attack chain
  [HUNT-QUERY] = Matched hunt query
================================================================================

[2025-10-20 14:23:45] Security Event 4688 [HIGH-CONFIDENCE] [ATTACK-CHAIN] [HUNT-QUERY]
  Computer: WORKSTATION-01
  User: DOMAIN\user
  Process: C:\Windows\System32\powershell.exe
  Source: Microsoft-Windows-Security-Auditing
  Description: A new process has been created...
--------------------------------------------------------------------------------

[2025-10-20 14:25:10] Security Event 4697 [HIGH-CONFIDENCE] [HIGH-RISK]
  Computer: WORKSTATION-01
  User: DOMAIN\admin
  Process:
  Source: Microsoft-Windows-Security-Auditing
  Service Name: MaliciousService
  Service Path: C:\Temp\malware.exe
  Description: A service was installed in the system...
--------------------------------------------------------------------------------

[2025-10-20 14:26:30] Security Event 4698 [HIGH-CONFIDENCE] [HUNT-QUERY]
  Computer: WORKSTATION-01
  User: DOMAIN\admin
  Process:
  Source: Microsoft-Windows-Security-Auditing
  Task Name: \Microsoft\Windows\UpdateTask
  Task Command: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\backdoor.ps1
  Description: A scheduled task was created...
--------------------------------------------------------------------------------
```

**Multiple Markers:** Events can have multiple markers if they match different criteria. For example, an event that is both a high-confidence indicator AND part of an attack chain will show: `[HIGH-CONFIDENCE] [ATTACK-CHAIN]`

**Enhanced Event Details:**
The tool automatically extracts and displays:
- **Service installations** (Event ID 4697, 7045): Service name and installation path
- **Scheduled tasks** (Event ID 4698, 106, 140, etc.): Task name, command, and arguments
- **Process creation**: Full process path and parent process
- **Network connections**: IP addresses and ports
- **Authentication**: Logon types and user accounts

**Benefits of This Approach:**
- Console output remains clean and easy to scan
- File export contains comprehensive details for investigation
- Markers help prioritize which events to investigate first
- Summaries provide quick overview of compromise indicators
- Service and task details aid in malware persistence detection

**Disclaimer:**
The compromise likelihood percentage is indicative only and represents a probabilistic assessment. Always conduct thorough manual investigation before drawing conclusions about system compromise.

#### Scoping & Export Guarantees
- **Strict Time-Window Filtering**: All console summaries (Detected Attack Chains, Hunt Query Matches, High‑Confidence Indicators, Critical High‑Risk Events, Category Breakdown) are computed strictly from the selected time window (`--date`, `--from-date/--to-date`, or `--hours`)
- **Universal Deduplication**: Events are deduplicated **once at the source** before being passed to chain detection, likelihood scoring, and console/file output—ensuring all metrics are consistent
- **Accurate Event Counts**: Console summaries and file export show identical deduplicated counts (e.g., if console shows "Event ID 4697: 25 occurrences", the export file contains exactly 25 unique events)
- **Export Safety**: While `--compromised` is active, the regular stdout export is disabled; only the compromise export writes to `-o` to avoid file conflicts/duplication
- **Likelihood Scoring Accuracy**: Compromise likelihood is calculated from deduplicated events only, preventing duplicate noise from inflating scores (e.g., a service that restarts 400 times = 1 unique event, not 400 separate attacks)

---

## Date-Based Searching

### Specific Date Search (`--date`)

Search for events from a specific date only instead of using a time window with `--hours`. The search covers the full 24-hour period (00:00:00 to 23:59:59) of the specified date.

**Search Single Date:**
```bash
# Search only events from December 31, 2025
python ThreatHunting.py --date 2025-12-31
```

**Compromise Assessment for Specific Date:**
```bash
# Check for compromise indicators on a specific day
python ThreatHunting.py --compromised --date 2025-10-20 --export-events -o oct20_assessment.txt
```

**Specific Date with Config:**
```bash
# Search for Sysmon events from a specific date
python ThreatHunting.py --date 2025-12-25 --config config/sysmon_core.json --format json
```

**Date Format:** YYYY-MM-DD

Key features:
- Overrides `--hours` parameter when both are specified
- Searches full 24-hour period of the date
- Works with all output formats (JSON, CSV, text, matrix)
- Compatible with all search modes (regular, compromised, remote hosts)
- Displays date search info in output:
  ```
  Searching for specific date: 2025-12-31 (full day)
  Time range: 2025-12-31 00:00:00 to 2025-12-31 23:59:59
  ```

### Date Range Search (`--from-date` and `--to-date`)

Search for events within a specific date range. Both arguments must be used together and override both `--hours` and `--date`.

**Basic Date Range:**
```bash
# Search events from January 1-7, 2026
python ThreatHunting.py --from-date 2026-01-01 --to-date 2026-01-07
```

**Compromise Assessment for Date Range:**
```bash
# Check for compromise indicators over a week
python ThreatHunting.py --compromised --from-date 2025-10-14 --to-date 2025-10-20 --export-events -o week_assessment.txt
```

**Extended Investigation Period:**
```bash
# Search Sysmon events over a month
python ThreatHunting.py --from-date 2025-12-01 --to-date 2025-12-31 --config config/sysmon_core.json
```

**Date Range with Exclusions:**
```bash
# Search a range but exclude specific dates (e.g., maintenance windows)
python ThreatHunting.py --from-date 2025-11-01 --to-date 2025-11-30 --exclude-date 2025-11-15 --exclude-date 2025-11-16
```

**Date Format:** YYYY-MM-DD

Key features:
- Both `--from-date` and `--to-date` are required when using date ranges
- Searches from 00:00:00 of `--from-date` to 23:59:59 of `--to-date`
- Overrides both `--hours` and `--date` parameters
- Validates that from-date is earlier than to-date
- Works with all output formats (JSON, CSV, text, matrix)
- Compatible with all search modes (regular, compromised, remote hosts)
- Displays date range info in output:
  ```
  Searching date range: 2026-01-01 to 2026-01-07
  Time range: 2026-01-01 00:00:00 to 2026-01-07 23:59:59
  ```

**Use Cases:**
- Investigate incidents on a known date
- Analyze activity during specific business days
- Compare events across different dates
- Audit historical activity
- Post-mortem analysis of specific dates

---

## Date Exclusion (`--exclude-date`)

Filter out events from specific dates during analysis. Useful for excluding known maintenance windows, scheduled updates, or non-business days.

**Exclude Single Date:**
```bash
python ThreatHunting.py --hours 72 --exclude-date 2025-12-25
```

**Exclude Multiple Dates:**
```bash
python ThreatHunting.py --compromised --hours 168 --exclude-date 2025-12-24 --exclude-date 2025-12-25 --exclude-date 2025-12-26
```

**Combined with Specific Date Search:**
```bash
# This doesn't make sense, but technically possible - search specific date while excluding it
# Better usage: search a range with --hours and exclude specific dates within that range
python ThreatHunting.py --hours 168 --exclude-date 2025-12-25 --exclude-date 2025-12-26
```

**Date Format:** YYYY-MM-DD

The exclusion filter:
- Removes events matching the specified date(s) from all results
- Works with all search modes (regular, compromised, remote hosts)
- Can be combined with `--hours` or `--date`
- Displays excluded dates in search parameters:
  ```
  Time range: 2025-12-20 10:00:00 to 2025-12-27 10:00:00
  Excluding dates: 2025-12-25, 2025-12-26
  ```

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
  - `ioc/lolbins_iocs.csv` curated LOLBins substrings and patterns.
  - `ioc/stix/common_stix.json` minimal STIX bundle with indicators.
  - Use with `--ioc` and `--ioc-format {csv,txt,stix}`.
  - Auto-update LOLBins IOCs: `python ThreatHunting.py --update-lolbas-iocs`

- `evtx/`:

  - Place sample `.evtx` files here (see `evtx/README.txt`) for offline hunting.
  - Use with `--evtx evtx` to scan the entire directory recursively.

- `hosts.txt` (create as needed):
  - List of remote hosts for multi-host hunting (one per line).
  - Use with `--hosts-file hosts.txt` for remote collection.

Quick commands:

```bash
# Sigma local matching
python ThreatHunting.py --hours 48 --all-events --sigma-dir sigma/windows --format text --matrix

# IOC CSV ingestion
python ThreatHunting.py --hours 24 --all-events --ioc ioc/common_iocs.csv --ioc-format csv --format json

# STIX JSON ingestion
python ThreatHunting.py --hours 24 --all-events --ioc ioc/stix/common_stix.json --ioc-format stix --format jsonl

# Update LOLBins IOCs from LOLBAS project
python ThreatHunting.py --update-lolbas-iocs

# Hunt with updated LOLBins IOCs
python ThreatHunting.py --hours 24 --all-events --ioc ioc/lolbins_iocs.csv --ioc-format csv --format text --matrix

# Offline EVTX hunting (directory)
python ThreatHunting.py --hours 168 --evtx evtx --all-events --format text --matrix

# Multi-host remote hunting
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.10 192.168.1.11 --username admin --format text --matrix
```

---

## Argument Reference

- `--hours <int>`: Time window to search backward from now (default: 24).
- `--date <YYYY-MM-DD>`: Search for events from a specific date only (full 24-hour period). Overrides `--hours`. Format: YYYY-MM-DD (e.g., `--date 2025-12-31`).
- `--from-date <YYYY-MM-DD>`: Start date for date range search. Must be used with `--to-date`. Overrides both `--hours` and `--date`.
- `--to-date <YYYY-MM-DD>`: End date for date range search. Must be used with `--from-date`. Overrides both `--hours` and `--date`.
- `--exclude-date <YYYY-MM-DD>`: Exclude events from specific date(s). Can be used multiple times (e.g., `--exclude-date 2025-12-25 --exclude-date 2025-12-26`). Works with all search modes and date options.
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
- `--update-lolbas-iocs`: Fetch latest LOLBAS catalog and generate ioc/lolbins_iocs.csv.
- `--lolbas-url <url>`: LOLBAS API URL (default: https://lolbas-project.github.io/api/lolbas.json).
- `--hosts <hosts>`: One or more remote hosts to query (IP addresses or hostnames).
- `--hosts-file <file>`: File containing list of remote hosts (one per line).
- `--timeout <seconds>`: Timeout in seconds for remote host connections (default: 30).
- `--parallel-hosts <num>`: Number of hosts to query in parallel (default: 5).
- `--username <user>`: Username for remote authentication.
- `--password <pass>`: Password for remote authentication (not recommended - use key-based auth).
- `--domain <domain>`: Domain for remote authentication.
- `--auth-method {winrm,wmi}`: Authentication method for remote hosts (default: winrm).
- `--auth-method {winrm,wmi,ssh}`: Authentication method for remote hosts (default: winrm).
- `--ssh-user <user>`: SSH username for `--auth ssh`.
- `--ssh-key <path>`: Path to SSH private key for `--auth ssh`.
- `--ssh-port <int>`: SSH port (default: 22).
- `--wef-endpoint <host>`: Windows Event Forwarding collector hostname/IP (queries `ForwardedEvents`).
- `--strict-remote`: Fail if remote collection fails or returns no results; no local fallback.
- `--sigma-dir <path>`: Directory with Sigma YAML rules to evaluate locally (simple selection support).
- `--sigma-boost <int>`: Score boost per matched Sigma rule (default 10).

Compromise hunting and assessment:

- `--compromised`: Enable automated compromise assessment mode using `config/compromise.json`. Analyzes event correlation chains, hunt queries, and high-confidence indicators to calculate compromise likelihood percentage. Provides detailed analysis report with attack chains, critical events, and category breakdowns. Includes interactive prompt to include additional config files for expanded hunting scope. **Always deduplicates events.**
- `--export-events`: Export all discovered events to file (use with `--compromised` and `-o <file>`). Creates detailed event listings with computer, user, process, source, and description fields. High-confidence indicators are marked with `[HIGH-CONFIDENCE]` tag.
- `--scoring-breakdown`: Show detailed scoring breakdown for compromise likelihood calculation. Displays event severity distribution, context analysis (LOLBin executions, privileged events, suspicious processes), attack chain details, and final likelihood calculation methodology.
- `--deduplicate`: Remove duplicate events from results in **regular search mode only** (compromise mode always deduplicates). Events are considered duplicates if they have the same date, event ID, log name, computer, and description. Displays count of removed duplicates.

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

### 0) **Automated Compromise Assessment (Recommended First Step)**

```bash
# Quick 24-hour assessment
python ThreatHunting.py --compromised --hours 24

# Extended 7-day assessment with detailed export
python ThreatHunting.py --compromised --hours 168 --export-events -o compromise_assessment.txt

# Exclude maintenance windows
python ThreatHunting.py --compromised --hours 72 --exclude-date 2025-10-20

# Investigate specific incident date
python ThreatHunting.py --compromised --date 2025-10-15 --export-events -o incident_oct15.txt

# Interactive config selection (prompts to include additional configs)
python ThreatHunting.py --compromised --date 2025-10-16

# With detailed scoring breakdown
python ThreatHunting.py --compromised --date 2025-10-16 --scoring-breakdown
```

```bash
# Strict scoping (verify output is only for the selected date)
python ThreatHunting.py --compromised --date 2025-10-17 --export-events -o only_17.txt
# PowerShell quick checks:
# Get-Content only_17.txt | Select-String "^\[2025-10-17 " | Measure-Object
# Get-Content only_17.txt | Select-String "^\[2025-10-(?!17)\d{2} " | Measure-Object
```

**What it does:**
- Automatically correlates events into attack chains
- Identifies high-confidence compromise indicators
- Calculates compromise likelihood percentage using advanced multi-factor scoring
- Prompts user to include additional config files for expanded hunting scope
- Provides detailed scoring breakdown with `--scoring-breakdown` flag
- Handles common events (DNS queries) intelligently to reduce false positives
- Provides structured analysis report
- Exports full event details with process information

**Recommended for:**
- Initial triage of suspected compromises
- Rapid assessment of unknown threats
- Post-incident validation
- Routine security checks

### 1) Broad suspicious activity sweep (last 24h)

```bash
python ThreatHunting.py --hours 24 --format text --matrix

# With deduplication to see only unique events
python ThreatHunting.py --hours 24 --format text --matrix --deduplicate
```

Tips:

- Scan with `--categories critical_smoking_gun_indicators` to focus on high-signal events.
- Add `--level Warning` or `--level Error` to reduce noise.
- Use `--deduplicate` to remove repeated events (e.g., services restarting multiple times) and focus on unique occurrences.

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

### Deduplication Comparison

**Without Deduplication (default in regular mode):**
```bash
# Shows all events including duplicates
python ThreatHunting.py --date 2025-10-17 --config config/simple_privilege.json

# Example output:
# Found 16,208 matching events  # ← Includes duplicates!
# Event ID 4697: 400 occurrences  # ← Service restarted 400 times
# Event ID 1100: 16 occurrences   # ← Log service stopped 16 times
```

**With Deduplication (--deduplicate flag):**
```bash
# Shows only unique events
python ThreatHunting.py --date 2025-10-17 --config config/simple_privilege.json --deduplicate

# Example output:
# [Deduplication] Removed 15,931 duplicate event(s), 277 unique event(s) remain
# Found 277 matching events  # ← Only unique events!
# Event ID 4697: 25 occurrences  # ← 25 unique service installations
# Event ID 1100: 1 occurrence    # ← 1 unique log service stop
```

**Compromise Mode (always deduplicated):**
```bash
# Automatically deduplicates all events
python ThreatHunting.py --compromised --date 2025-10-17

# Output always shows deduplicated counts
# Total Events Found: 277
# Compromise Likelihood: 23.5% (accurate, not inflated by duplicates)
```

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

````bash
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

# LOLBins hunting recipes

```bash
# Broad LOLBins sweep (last 24h)
python ThreatHunting.py --hours 24 --all-events --process-filter "powershell\.exe|cmd\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|bitsadmin\.exe|schtasks\.exe|wmic\.exe" --format text --matrix

# LOLBins with suspicious command-line substrings (base64, AMSI bypass, download cradles)
python ThreatHunting.py --hours 24 --all-events --process-filter "powershell\.exe|cmd\.exe|mshta\.exe|rundll32\.exe" --description-filter " -enc |FromBase64String|bypass|amsi|downloadstring|bitsadmin " --format json

# Office spawning LOLBins (parent-child anomaly)
python ThreatHunting.py --hours 48 --all-events --parent-filter "winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe" --process-filter "powershell\.exe|rundll32\.exe|regsvr32\.exe|cmd\.exe|mshta\.exe" --format text --matrix

# Sigma-assisted LOLBins (use included rules) with score boost
python ThreatHunting.py --hours 48 --all-events --sigma-dir sigma/windows --sigma-boost 15 --format text --matrix

# Timeline view for LOLBin activity by user (quick narrative)
python ThreatHunting.py --hours 24 --all-events --process-filter "powershell\.exe|cmd\.exe|rundll32\.exe" --timeline jsonl --sessionize user > lolbin_user_timeline.jsonl

# Narrow to execution/defense-evasion category (lower noise)
python ThreatHunting.py --hours 24 --categories execution_and_defense_evasion --process-filter "powershell\.exe|rundll32\.exe|regsvr32\.exe" --format text --matrix

# Offline EVTX triage for LOLBins
python ThreatHunting.py --hours 168 --evtx evtx --all-events --process-filter "powershell\.exe|cmd\.exe|rundll32\.exe" --format text --matrix

# Raise signal by combining levels and allowlist to suppress noise
python ThreatHunting.py --hours 24 --all-events --levels-all Information Warning --allowlist config/allowlist.json --process-filter "powershell\.exe|cmd\.exe|rundll32\.exe" --format text --matrix

# IOC-driven LOLBin substrings (use provided ioc/lolbins_iocs.csv)
python ThreatHunting.py --hours 24 --all-events --ioc ioc/lolbins_iocs.csv --ioc-format csv --format text --matrix

# Update LOLBins IOCs from latest LOLBAS catalog
python ThreatHunting.py --update-lolbas-iocs

# Hunt with freshly updated LOLBins IOCs
python ThreatHunting.py --hours 24 --all-events --ioc ioc/lolbins_iocs.csv --ioc-format csv --format text --matrix
````

# Offline EVTX hunting across a directory of files (triage bundle)

```bash
python ThreatHunting.py --hours 168 --evtx C:\\triage\\evtx_dump --all-events --format text --matrix

# Advanced combinations and edge cases

# Multiple configs with preset
python ThreatHunting.py --hours 24 --preset incident_response --configs config/privilege_escalation.json config/accessible_events.json --format json

# Complex field filtering with boolean logic
python ThreatHunting.py --hours 48 --all-events --process-filter "powershell\\.exe|cmd\\.exe" --parent-filter "winword\\.exe|excel\\.exe" --bool OR --format text --matrix

# Timeline with sessionization and output to file
python ThreatHunting.py --hours 72 --all-events --timeline jsonl --sessionize user --format jsonl > user_timeline.jsonl

# High-performance scanning with concurrency and progress
python ThreatHunting.py --hours 168 --all-events --max-events 10000 --concurrency 4 --progress --format json

# Comprehensive hunting with all features
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --ioc ioc/lolbins_iocs.csv --ioc-format csv --allowlist config/allowlist.json --levels-all Information Warning Error --format text --matrix --progress

# Service status check
python ThreatHunting.py --check-service

# Webhook integration
python ThreatHunting.py --hours 24 --all-events --webhook https://your-webhook.com/endpoint --format jsonl

# Splunk HEC integration
python ThreatHunting.py --hours 24 --all-events --hec-url https://your-splunk.com:8088/services/collector --hec-token your-token --format jsonl

# Suppression rules
python ThreatHunting.py --hours 24 --all-events --suppress "Application/600" --suppress "System/7036" --format text

# Specific event ID hunting
python ThreatHunting.py --hours 24 --event-ids 4624 4625 4648 4672 --format text --matrix

# Category-based hunting with custom config
python ThreatHunting.py --hours 24 --categories credential_access,lateral_movement --config config/custom_events.json --format json

# Retention configuration
python ThreatHunting.py --configure-retention --log Security --size 100MB --days 30

# Log availability check
python ThreatHunting.py --check-availability

# Auto-elevation
python ThreatHunting.py --elevate --hours 24 --all-events --format text

# Quiet mode with minimal output
python ThreatHunting.py --hours 24 --all-events --format json --quiet

# Verbose mode with detailed output
python ThreatHunting.py --hours 24 --all-events --format text --verbose

# Multi-host/remote collection examples

# Query multiple remote hosts via WinRM
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.10 192.168.1.11 192.168.1.12 --username admin --password secret --format text --matrix

# Query hosts from file with custom timeout and parallel processing
python ThreatHunting.py --hours 48 --all-events --hosts-file hosts.txt --timeout 60 --parallel-hosts 10 --username domain\\admin --format json

# Remote hunting with WMI authentication
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.100 --auth-method wmi --username admin --password secret --format text --matrix

# Remote hunting with SSH key auth (PowerShell 7 + SSH server on hosts)
python ThreatHunting.py --hours 24 --all-events --hosts 10.0.0.5 10.0.0.6 --auth-method ssh --ssh-user azureuser --ssh-key C:\\Users\\you\\.ssh\\id_ed25519 --ssh-port 22 --format text --matrix

# Enforce strict-remote (no local fallback if remote fails)
python ThreatHunting.py --hours 1 --all-events --hosts 10.8.200.17 --auth-method ssh --ssh-user azureuser --ssh-key C:\\Users\\you\\.ssh\\id_ed25519 --strict-remote --format text --matrix

# Strict-remote with WinRM
python ThreatHunting.py --hours 2 --all-events --hosts 192.168.1.50 192.168.1.60 --auth-method winrm --username .\\LocalAdmin --password "StrongP@ss!" --strict-remote --format json

# Strict-remote with WMI
python ThreatHunting.py --hours 2 --all-events --hosts-file hosts.txt --auth-method wmi --username DOMAIN\\ir --password "Secret" --strict-remote --format text --matrix

# Remote hunting with specific categories and field filtering
python ThreatHunting.py --hours 24 --categories credential_access,lateral_movement --hosts 192.168.1.10 192.168.1.11 --process-filter "powershell\\.exe" --format json

# Remote hunting with Sigma rules and IOCs
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.10 --sigma-dir sigma/windows --ioc ioc/lolbins_iocs.csv --ioc-format csv --format text --matrix

# Remote hunting with timeline output
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.10 192.168.1.11 --timeline jsonl --sessionize user --format jsonl

# Remote hunting with allowlist suppression
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.10 --allowlist config/allowlist.json --format text --matrix

# Remote hunting with webhook integration
python ThreatHunting.py --hours 24 --all-events --hosts 192.168.1.10 192.168.1.11 --webhook https://your-webhook.com/endpoint --format jsonl

# Query a central WEF collector (ForwardedEvents)
python ThreatHunting.py --hours 24 --all-events --wef-endpoint wef-collector.yourcorp.local --format text --matrix

Tips:
- On Windows paths, escape backslashes in key paths, e.g. `C:\\Users\\you\\.ssh\\id_ed25519`.
- Verify remote results by checking the Computer column shows the remote host.
```

### Sigma rules examples

```bash
# Load local Sigma rules folder and boost scores for matches
python ThreatHunting.py --hours 48 --all-events --sigma-dir sigma/windows --sigma-boost 15 --format text --matrix

# Combine Sigma with explicit Event IDs and ship matches via JSONL webhook
python ThreatHunting.py --hours 24 --event-ids 4688 7045 1102 --sigma-dir sigma/windows --format jsonl --webhook https://example.org/hook

# Use Sigma alongside allowlist suppression to reduce noise
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --allowlist config/allowlist.json --format json

# Sigma rules with field filtering
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --process-filter "powershell\\.exe" --format text --matrix

# Sigma rules with timeline output
python ThreatHunting.py --hours 24 --all-events --sigma-dir sigma/windows --timeline jsonl --format jsonl

# Sigma rules with specific categories
python ThreatHunting.py --hours 24 --categories execution_and_defense_evasion --sigma-dir sigma/windows --format text --matrix
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

# IOC hunting with field filtering
python ThreatHunting.py --hours 24 --all-events --ioc ioc/lolbins_iocs.csv --ioc-format csv --process-filter "powershell\\.exe" --format text --matrix

# IOC hunting with timeline output
python ThreatHunting.py --hours 24 --all-events --ioc ioc/common_iocs.csv --ioc-format csv --timeline jsonl --format jsonl

# IOC hunting with boost scores
python ThreatHunting.py --hours 24 --all-events --ioc ioc/lolbins_iocs.csv --ioc-format csv --ioc-boost 15 --format text --matrix
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

| Event ID            | What it is                                          | Why hunt for it                                                                      |
| ------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------ |
| 4624                | An account was successfully logged on               | Baseline logons, pivot by LogonType for network/RDP/service logons, lateral movement |
| 4625                | An account failed to log on                         | Password spraying/brute force indicators, failed lateral movement                    |
| 4634                | An account was logged off                           | Session lifecycle correlation with 4624/4648                                         |
| 4648                | A logon was attempted using explicit credentials    | Pass-the-Hash/Ticket usage, remote exec tools (PsExec/WMI)                           |
| 4672                | Special privileges assigned to new logon            | Admin-equivalent context; privilege escalation and high-value sessions               |
| 4673–4674           | Sensitive privilege use / Privileged service called | Detection of privilege API usage by processes                                        |
| 4697                | A service was installed in the system               | Persistence, privilege escalation, remote service creation                           |
| 4698                | A scheduled task was created                        | Persistence, living-off-the-land tasking                                             |
| 4732/4728/4756      | Member added to local/global/universal group        | Privilege escalation via group membership changes                                    |
| 4768/4769/4771      | Kerberos TGT/TGS request/failure                    | Kerberoasting, clock skew, KDC issues, brute forcing                                 |
| 4772/4773/4774/4775 | Kerberos auth anomalies                             | Ticket renewals/failures, policy issues, potential abuse                             |
| 4776                | NTLM authentication                                 | Legacy auth, relay risk, brute force indicators                                      |
| 1102                | The audit log was cleared                           | High-signal defense evasion                                                          |

### Windows System/Application - Services, Tasks, Registry, Shares

| Event ID                 | What it is                                | Why hunt for it                                       |
| ------------------------ | ----------------------------------------- | ----------------------------------------------------- |
| 7040                     | Service start type changed                | Persistence via autorun service changes               |
| 7045                     | A service was installed (System)          | Persistence/remote execution, tool staging            |
| 106/140 (Task Scheduler) | Task created/updated                      | Persistence and scheduled execution                   |
| 12/13/14 (Registry)      | Registry value/key added/modified         | Autoruns, tampering with security controls            |
| 4688                     | Process creation                          | Parent-child anomalies, LOLBins, malware invocations  |
| 4689                     | Process termination                       | Correlate lifetimes, short-lived suspicious processes |
| 5140/5142/5145           | SMB share accessed/created/object checked | Lateral movement, data staging/exfil over SMB         |
| 4778/4779                | Session reconnect/disconnect              | RDP/interactive session tracking                      |

### PowerShell and Script Execution

| Event ID          | What it is                              | Why hunt for it                                                     |
| ----------------- | --------------------------------------- | ------------------------------------------------------------------- |
| 4100              | PowerShell engine lifecycle             | Baseline session/activity presence                                  |
| 4103              | PowerShell module logging               | Cmdlet/module usage; detect living-off-the-land                     |
| 4104              | PowerShell script block logging         | High-signal malicious script content (obfuscation, download cradle) |
| 53504/53506/53507 | PowerShell operational (newer channels) | Deep telemetry for script operations (if enabled)                   |

### Windows Filtering Platform (Network)

| Event ID            | What it is                     | Why hunt for it                                       |
| ------------------- | ------------------------------ | ----------------------------------------------------- |
| 5152/5153           | Packet blocked by filter       | Host-based firewall blocks; scanning, failed C2       |
| 5156                | Connection allowed             | Baseline outbound/inbound; unusual destinations/ports |
| 5157                | Connection blocked             | Egress control efficacy; policy tamper attempts       |
| 5158/5159/5160/5161 | Resource assignments and state | Low-level flow diagnostics; advanced network hunting  |

### Windows Defender (Microsoft Defender AV)

| Event ID | What it is               | Why hunt for it                                         |
| -------- | ------------------------ | ------------------------------------------------------- |
| 1116     | Malware detected         | Direct detection signal; pivot to related process/file  |
| 1117     | Remediation action taken | Cleanup actions; verify success and residual indicators |

### RDP and Remote Access (Terminal Services)

| Event ID | What it is                                 | Why hunt for it                               |
| -------- | ------------------------------------------ | --------------------------------------------- |
| 1149     | Successful RDP logon (TS-Gateway/TermServ) | Trace interactive access, brute force success |
| 21/24/25 | Session connect/disconnect/reconnect       | Account usage patterns, suspicious timing     |

### Sysmon (if deployed)

| Event ID             | What it is                       | Why hunt for it                                  |
| -------------------- | -------------------------------- | ------------------------------------------------ |
| 1                    | Process creation                 | Parent-child chains, command-lines, LOLBins      |
| 2                    | File creation time changed       | Timestomping detection                           |
| 3                    | Network connection               | Outbound C2, lateral movement, rare destinations |
| 4                    | Sysmon service state changed     | Tamper and defense evasion                       |
| 5                    | Process terminated               | Lifecycle correlation with Event ID 1            |
| 6                    | Driver loaded                    | Kernel-mode implants, unsigned drivers           |
| 7                    | Image loaded                     | Malicious DLLs, injection indicators             |
| 8                    | CreateRemoteThread               | Code injection between processes                 |
| 9                    | Raw disk access                  | Ransomware behavior, low-level tampering         |
| 10                   | Process access (e.g., lsass.exe) | Credential theft tooling (Mimikatz, etc.)        |
| 11                   | File created                     | Payload drops, staging                           |
| 12/13/14             | Registry add/delete/set          | Autoruns and tampering                           |
| 15                   | File stream created              | ADS usage for stealth                            |
| 16                   | Sysmon configuration change      | Tamper and logging gaps                          |
| 17/18                | Pipe created/connected           | Lateral tools, inter-process comms               |
| 19/20/21/22/23/24/25 | WMI event activity               | Remote exec, persistence via WMI                 |

### Other and Category Placeholders

| Event ID                          | What it is                                                    | Why hunt for it                                                            |
| --------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 400/403/600                       | Provider-specific placeholders used in configs                | Treat as hints to inspect provider channels relevant to execution/remoting |
| 1000–1050 (Application)           | Common application crash/errors                               | Unusual instability tied to attack tooling                                 |
| 6005/6006/6008/6009 (System)      | Event log service start/stop; unexpected shutdown; OS version | Establish uptime and suspicious reboots                                    |
| 6011–6050 (System)                | System telemetry sequence                                     | Operational context; correlate with attack timelines                       |
| 4673–5000 (Security, broad range) | Detailed privilege/use-of-rights and audit events             | Exhaustive reviews during deep IR; pivot selectively by activity           |

### Additional high-signal account change events (Security)

| Event ID | What it is                 | Why hunt for it                                  |
| -------- | -------------------------- | ------------------------------------------------ |
| 4720     | User account created       | Unauthorized local admin creation; staging users |
| 4726     | User account deleted       | Covering tracks; suspicious cleanup              |
| 4738     | User account changed       | Privilege/tamper of user properties              |
| 4767     | Account unlocked           | Brute-force recovery; suspicious unlock patterns |

### Windows Logon Type reference (Security 4624/4625)

| Logon Type | Meaning           |
| ---------- | ----------------- |
| 2          | Interactive       |
| 3          | Network           |
| 4          | Batch             |
| 5          | Service           |
| 7          | Unlock            |
| 8          | NetworkCleartext  |
| 9          | NewCredentials    |
| 10         | RemoteInteractive |
| 11         | CachedInteractive |

### Common LOLBins and suspicious flags (execution/defense evasion)

| Binary         | Suspicious flags/patterns                       |
| -------------- | ----------------------------------------------- |
| powershell.exe | -enc, IEX, DownloadString, AMSI bypass keywords |
| regsvr32.exe   | /s scrobj.dll                                   |
| rundll32.exe   | javascript:, unusual DLL exports                |
| mshta.exe      | http/https scriptlets                           |
| certutil.exe   | -urlcache -f, -decode                           |
| bitsadmin.exe  | /transfer                                       |

### Remote collection authentication quick matrix

| Auth/Account type           | WinRM | WMI | SSH (PS7+SSHD) | Notes                                           |
| --------------------------- | ----- | --- | -------------- | ----------------------------------------------- |
| Local admin (user+password) | Yes   | Yes | Yes            | Recommended baseline                            |
| Domain account              | Yes   | Yes | Yes            | Works on domain/hybrid joined                   |
| AzureAD user + PIN (Hello)  | No    | No  | Keys only      | Use SSH keys or cert-mapped WinRM HTTPS         |
| AzureAD user + certificate  | HTTPS | No  | Keys           | WinRM HTTPS with client cert mapping required   |
