#! /usr/bin/env python3

import win32evtlog
import win32evtlogutil
import win32con
import win32api
import win32security
import subprocess
import tempfile
from datetime import datetime, timedelta
import json
import sys
import os
from contextlib import redirect_stdout
import ctypes
import re
import json as _json
import socket
try:
    import yaml
except Exception:
    yaml = None
try:
    from Evtx.Evtx import Evtx as EvtxReader
except Exception:
    EvtxReader = None
import xml.etree.ElementTree as ET
try:
    import requests
except Exception:
    requests = None
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    Fore = None
    Style = None
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from tqdm import tqdm
except Exception:
    tqdm = None


def load_event_ids_from_json(json_file_path):
    """Load Event IDs from a JSON configuration file"""
    try:
        with open(json_file_path, 'r') as f:
            events = json.load(f)
        print(f"Loaded Event IDs from: {json_file_path}")
        return events
    except FileNotFoundError:
        print(
            f"Error: Event ID configuration file not found: {json_file_path}")
        return None


def validate_config_schema(cfg):
    """Validate that cfg is a mapping of category -> list[int]."""
    if not isinstance(cfg, dict):
        return False, "Config root must be an object mapping categories to lists."
    for cat, ids in cfg.items():
        if not isinstance(cat, str):
            return False, f"Invalid category name type: {type(cat)}"
        if not isinstance(ids, list):
            return False, f"Category '{cat}' must map to a list of integers."
        for eid in ids:
            if not isinstance(eid, int):
                return False, f"Category '{cat}' contains non-integer event id: {repr(eid)}"
    return True, None


def merge_configs_with_diff(base_cfg, override_cfg):
    """Merge override_cfg into base_cfg. Return (merged, diff) where diff describes added cats/ids."""
    merged = {k: list(v) for k, v in (base_cfg or {}).items()}
    diff = {'new_categories': [], 'updated_categories': {}}
    for cat, ids in (override_cfg or {}).items():
        ids_set = set(ids)
        if cat not in merged:
            merged[cat] = sorted(ids_set)
            diff['new_categories'].append(cat)
        else:
            before = set(merged[cat])
            added = ids_set - before
            if added:
                merged[cat] = sorted(before | ids_set)
                diff['updated_categories'][cat] = sorted(added)
    return merged, diff


def print_config_diff(diff, quiet=False):
    if quiet:
        return
    try:
        if diff.get('new_categories'):
            print("Added categories:", ', '.join(diff['new_categories']))
        if diff.get('updated_categories'):
            print("Updated categories (added Event IDs):")
            for cat, added in diff['updated_categories'].items():
                print(
                    f"  {cat}: +{len(added)} -> {added[:10]}{'...' if len(added) > 10 else ''}")
    except Exception:
        pass
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        return None
    except Exception as e:
        print(f"Error loading Event ID configuration: {e}")
        return None


def get_default_events():
    """Get default Event IDs if no JSON file is provided"""
    return {
        "credential_access_and_privilege_escalation": [
            4624,  # Logon success
            4625,  # Logon failure
            4648,  # Logon with explicit credentials
            4672,  # Special privileges assigned
            4688,  # Process creation
            4697,  # Service installation (Security)
            7045,  # Service installed (System)
            4732,  # Member added to a privileged local group
            4728,  # Member added to global group (privilege group)
            4756,  # Member added to universal group
            1102,  # Audit log cleared
        ],

        "persistence_and_startup_modification": [
            # Process creation (already listed above) - kept so category is self-contained
            4688,
            7040,  # Service configuration changed
            7045,  # Service installed (dup)
            12,    # (mentioned) registry/startup related IDs in checklist
            13,    # (mentioned)
            14,    # (mentioned)
            106,   # TaskScheduler - task created/modified (mentioned)
            140,   # TaskScheduler - task created/modified (mentioned)
            4698,  # Scheduled task creation (also a smoking-gun indicator)
        ],

        "lateral_movement_and_remote_access": [
            4624,  # Logon success (network / RDP types)
            4648,  # Explicit credential use (lateral movement)
            4776,  # Credential validation using NTLM
            5140,  # Network share object accessed
            5142,  # Network share created
            5145,  # File share object checked/accessed
            7045,  # Service installed remotely
        ],

        "execution_and_defense_evasion": [
            4688,  # Process creation
            4689,  # Process termination
            4104,  # PowerShell Script Block Logging
            4103,  # PowerShell Module Logging / pipeline events
            600,   # WMI / WinRM activity (mentioned)
            4100,  # PowerShell engine events (mentioned)
            1116,  # Windows Defender detection events (example)
            1117,  # Windows Defender remediation actions (example)
        ],

        "exfiltration_and_c2": [
            5156,  # Windows Filtering Platform — allowed connection
            5157,  # Windows Filtering Platform — blocked connection
            # Process creation showing data transfer tools (curl/certutil/powershell)
            4688,
            # (mentioned in checklist) — e.g., Sysmon-like network/file events (kept as mentioned)
            400,
            403,   # (mentioned)
            600,   # (again) WMI / other activity used for remote exec or transfer
        ],

        "critical_smoking_gun_indicators": [
            1102,  # Audit logs cleared
            4698,  # Scheduled task created
            7045,  # Service installed
            4688,  # Suspicious process creation
            10,    # Sysmon 10 (LSASS/process access)
            4104,  # Malicious PowerShell script block
            4732,  # Privileged group membership changes
            4728,  # Privileged group membership changes (dup)
            5156,  # Unusual outbound connections
            5157,  # Suspicious blocked/allowed connections
        ],

        "correlation_and_hunting_helpers": [
            4689,  # Process termination
            4624,  # Logon success
            4625,  # Logon failure
            4648,  # Explicit credential use
            4776,  # NTLM auth attempts
            5140,  # Share access
            5145,  # Share/file access
        ],
    }


# Global variable to store loaded events - initialize with defaults
EVENTS = None
ALL_EVENT_IDS = None


class WindowsEventLogSearcher:
    def __init__(self, sigma_rules=None, sigma_boost=10, iocs=None, ioc_boost=5,
                 remote_hosts=None, timeout=30, parallel_hosts=5, username=None,
                 password=None, domain=None, auth_method='winrm', exclude_dates=None, lolbins_set=None):
        self.logs = ['Application', 'Security', 'Setup', 'System']
        self.results = []
        self.sigma_rules = sigma_rules or []
        self.sigma_boost = sigma_boost
        self.iocs = iocs or {'ips': set(), 'domains': set(),
                             'hashes': set(), 'substrings': set()}
        self.ioc_boost = ioc_boost
        self.ioc_hits_counter = {}
        self.lolbins_set = lolbins_set or set()  # Set of LOLBin executable names from lolbins_iocs.csv
        self.remote_hosts = remote_hosts or []
        self.timeout = timeout
        self.parallel_hosts = parallel_hosts
        self.username = username
        self.password = password
        self.domain = domain
        self.auth_method = auth_method
        self.exclude_dates = exclude_dates or []

    def _query_remote_host(self, host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events):
        """Query a single remote host for event logs"""
        try:
            if self.auth_method == 'winrm':
                return self._query_remote_winrm(host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events)
            elif self.auth_method == 'wmi':
                return self._query_remote_wmi(host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events)
            elif self.auth_method == 'ssh':
                return self._query_remote_ssh(host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events)
        except Exception as e:
            print(f"Error querying host {host}: {e}")
            return []

    def _query_remote_winrm(self, host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events):
        """Query remote host using WinRM"""
        try:
            # Build PowerShell command for remote execution
            ps_cmd = self._build_remote_powershell_command(
                event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events)

            # Use winrs for remote execution
            cmd = f'winrs -r:{host} -u:{self.username or ""} -p:{self.password or ""} powershell -Command "{ps_cmd}"'

            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode == 0:
                # Parse the JSON output from remote host
                try:
                    remote_results = json.loads(result.stdout)
                    # Add host information to each result
                    for event in remote_results:
                        event['remote_host'] = host
                    return remote_results
                except json.JSONDecodeError:
                    print(f"Failed to parse JSON from host {host}")
                    return []
            else:
                print(f"Remote command failed on {host}: {result.stderr}")
                return []

        except subprocess.TimeoutExpired:
            print(f"Timeout querying host {host}")
            return []
        except Exception as e:
            print(f"Error querying host {host} via WinRM: {e}")
            return []

    def _query_remote_wmi(self, host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events):
        """Query remote host using WMI"""
        try:
            # Build WMI query for remote execution
            wmi_query = self._build_remote_wmi_query(event_ids, hours_back, level_filter, level_all,
                                                     log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events)

            # Use wmic for remote execution
            cmd = f'wmic /node:"{host}" /user:"{self.username or ""}" /password:"{self.password or ""}" path Win32_NTLogEvent where "{wmi_query}" get /format:csv'

            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode == 0:
                # Parse the CSV output from remote host
                return self._parse_wmi_csv_output(result.stdout, host)
            else:
                print(f"WMI query failed on {host}: {result.stderr}")
                return []

        except subprocess.TimeoutExpired:
            print(f"Timeout querying host {host}")
            return []
        except Exception as e:
            print(f"Error querying host {host} via WMI: {e}")
            return []

    def _build_remote_powershell_command(self, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events):
        """Build PowerShell command for remote execution"""
        # This is a simplified version - in practice, you'd want to embed the full search logic
        cmd_parts = [
            "Get-WinEvent -FilterHashtable @{",
            f"LogName='{','.join(log_filter or self.logs)}';",
            f"StartTime=(Get-Date).AddHours(-{hours_back})",
        ]

        if not level_all and event_ids:
            cmd_parts.append(f";ID={','.join(map(str, event_ids))}")

        if level_filter:
            cmd_parts.append(f";Level={level_filter}")

        cmd_parts.append("} | ConvertTo-Json -Depth 3")

        return "".join(cmd_parts)

    def _build_remote_wmi_query(self, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events):
        """Build WMI query for remote execution"""
        conditions = []

        if not level_all and event_ids:
            event_id_condition = " or ".join(
                [f"EventCode={eid}" for eid in event_ids])
            conditions.append(f"({event_id_condition})")

        if level_filter:
            conditions.append(f"Type='{level_filter}'")

        if log_filter:
            log_condition = " or ".join(
                [f"LogFile='{log}'" for log in log_filter])
            conditions.append(f"({log_condition})")

        # Add time filter (simplified)
        time_filter = f"TimeGenerated>='{datetime.now() - timedelta(hours=hours_back)}'"
        conditions.append(time_filter)

        return " and ".join(conditions)

    def _parse_wmi_csv_output(self, csv_output, host):
        """Parse WMI CSV output and convert to standard format"""
        results = []
        lines = csv_output.strip().split('\n')

        if len(lines) < 2:
            return results

        # Skip header line
        for line in lines[1:]:
            if line.strip():
                # Parse CSV line and convert to standard event format
                # This is simplified - you'd need to map WMI fields to standard event fields
                parts = line.split(',')
                if len(parts) >= 5:
                    event = {
                        'remote_host': host,
                        'EventID': parts[0] if parts[0] else 'Unknown',
                        'TimeGenerated': parts[1] if parts[1] else 'Unknown',
                        'LogName': parts[2] if parts[2] else 'Unknown',
                        'Source': parts[3] if parts[3] else 'Unknown',
                        'Message': parts[4] if parts[4] else 'Unknown'
                    }
                    results.append(event)

        return results

    def _query_remote_ssh(self, host, event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events):
        """Query remote host using SSH PowerShell remoting (requires PowerShell 7 + SSH server)"""
        try:
            # Build PowerShell command to run remotely
            ps_cmd = self._build_remote_powershell_command(
                event_ids, hours_back, level_filter, level_all, log_filter, source_filter, description_filter, field_filters, bool_logic, negate, max_events)
            # Escape quotes for SSH
            ps_cmd_escaped = ps_cmd.replace('"', '\\"')
            ssh_user = self.username or ''
            key_arg = f" -i \"{self._normalize_path(self.ssh_key)}\"" if getattr(
                self, 'ssh_key', None) else ''
            port_arg = f" -p {getattr(self, 'ssh_port', 22)}" if getattr(
                self, 'ssh_port', None) else ''
            user_host = f"{ssh_user}@{host}" if ssh_user else host
            cmd = f"ssh -o BatchMode=yes -o ConnectTimeout={self.timeout}{port_arg}{key_arg} {user_host} powershell -NoProfile -Command \"{ps_cmd_escaped}\""
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
            if result.returncode == 0:
                try:
                    remote_results = json.loads(result.stdout)
                    for event in remote_results:
                        event['remote_host'] = host
                    return remote_results
                except json.JSONDecodeError:
                    print(f"Failed to parse JSON from host {host} (SSH)")
                    return []
            else:
                print(f"SSH command failed on {host}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"Timeout querying host {host} via SSH")
            return []
        except Exception as e:
            print(f"Error querying host {host} via SSH: {e}")
            return []

    def _normalize_path(self, p):
        try:
            return os.path.abspath(os.path.expanduser(p))
        except Exception:
            return p

    def search_remote_hosts(self, event_ids, hours_back=24, output_format='json', level_filter=None, level_all=False, matrix_format=False, log_filter=None, source_filter=None, description_filter=None, quiet=False, field_filters=None, bool_logic='and', negate=False, max_events=0, progress=False, allowlist=None, suppress_rules=None):
        """Search for events across multiple remote hosts"""
        if not self.remote_hosts:
            print("No remote hosts specified")
            return []

        print(f"Querying {len(self.remote_hosts)} remote hosts...")
        all_results = []

        # Use ThreadPoolExecutor for parallel host queries
        with ThreadPoolExecutor(max_workers=self.parallel_hosts) as executor:
            # Submit tasks for each host
            future_to_host = {
                executor.submit(
                    self._query_remote_host,
                    host, event_ids, hours_back, level_filter, level_all,
                    log_filter, source_filter, description_filter, field_filters,
                    bool_logic, negate, max_events
                ): host for host in self.remote_hosts
            }

            # Collect results as they complete
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    host_results = future.result()
                    all_results.extend(host_results)
                    if not quiet:
                        print(
                            f"Retrieved {len(host_results)} events from {host}")
                except Exception as e:
                    print(f"Error processing results from {host}: {e}")

        # Process results with local filtering and scoring
        self.results = all_results
        self._apply_local_processing()

        return all_results

    def _apply_local_processing(self):
        """Apply local processing (scoring, Sigma rules, IOCs) to remote results"""
        for event in self.results:
            # Apply scoring
            event['score'] = self._score_event(event)
            event['risk_reasons'] = self._get_risk_reasons(event)

            # Apply Sigma rules
            self._apply_sigma_rules(event)

            # Apply IOCs
            self._apply_iocs(event)

    def search_event_ids(self, event_ids, hours_back=24, output_format='json', level_filter=None, level_all=False, matrix_format=False, log_filter=None, 
                         source_filter=None, description_filter=None, quiet=False, field_filters=None, bool_logic='and', negate=False, max_events=0, concurrency=1, progress=False, allowlist=None, suppress_rules=None, specific_date=None, from_date=None, to_date=None):
        """
        Search for specific Event IDs in Windows Event Logs

        Args:
            event_ids (list): List of Event IDs to search for
            hours_back (int): How many hours back to search (default: 24)
            specific_date (str): Search only events from a specific date (YYYY-MM-DD), overrides hours_back
            from_date (str): Start date for date range (YYYY-MM-DD), use with to_date
            to_date (str): End date for date range (YYYY-MM-DD), use with from_date
            output_format (str): Output format - 'json', 'text', or 'csv'
            level_filter (str): Filter events by level (Error, Warning, Information, etc.)
            level_all (bool): If True, search for all events of the specified level, ignoring Event ID filter
            matrix_format (bool): If True, display results in matrix format
            log_filter (str): Filter results to specific log type
            source_filter (str): Filter results where source contains this string
            description_filter (str): Filter results where description contains this string
        """
        # Handle date range if provided
        if from_date and to_date:
            try:
                # Parse the date range
                start_date = datetime.strptime(from_date, '%Y-%m-%d')
                end_date = datetime.strptime(to_date, '%Y-%m-%d')
                start_time = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_time = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
                if start_time > end_time:
                    print(f"Error: --from-date ({from_date}) must be earlier than --to-date ({to_date}).")
                    return
            except ValueError as e:
                print(f"Error: Invalid date format. Expected YYYY-MM-DD. {e}")
                return
        elif from_date or to_date:
            print("Error: Both --from-date and --to-date must be specified together.")
            return
        # Handle specific date if provided (and no date range)
        elif specific_date:
            try:
                # Parse the specific date and set time range to that full day
                target_date = datetime.strptime(specific_date, '%Y-%m-%d')
                start_time = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_time = target_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            except ValueError:
                print(f"Error: Invalid date format '{specific_date}'. Expected YYYY-MM-DD.")
                return
        else:
            start_time = datetime.now() - timedelta(hours=hours_back)
            end_time = datetime.now()

        if not quiet:
            if level_all:
                print(
                    f"Searching for ALL {level_filter} events (ignoring Event ID filter)")
            else:
                print(f"Searching for Event IDs: {event_ids}")
                if level_filter:
                    print(f"Level filter: {level_filter}")
            if from_date and to_date:
                print(f"Searching date range: {from_date} to {to_date}")
            elif specific_date:
                print(f"Searching for specific date: {specific_date} (full day)")
            print(
                f"Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Logs: {', '.join(self.logs)}")
            if self.exclude_dates:
                print(f"Excluding dates: {', '.join(self.exclude_dates)}")
            print("-" * 80)

        self.level_filter = level_filter
        self.level_all = level_all
        self.matrix_format = matrix_format
        self.log_filter = log_filter
        self.source_filter = source_filter
        self.description_filter = description_filter
        self.quiet = quiet
        self.field_filters = field_filters or {}
        self.bool_logic = bool_logic
        self.negate = negate
        self.max_events = max_events if isinstance(
            max_events, int) and max_events >= 0 else 0
        self.allowlist = allowlist or {}
        self.suppress_rules = suppress_rules or []

        # If EVTX mode, override logs handling
        self.evtx_paths = getattr(
            args, 'evtx', None) if 'args' in globals() else None
        if self.evtx_paths:
            # Offline parsing mode
            files = []
            for p in self.evtx_paths:
                if os.path.isdir(p):
                    for root, _, fs in os.walk(p):
                        for fn in fs:
                            if fn.lower().endswith('.evtx'):
                                files.append(os.path.join(root, fn))
                elif os.path.isfile(p) and p.lower().endswith('.evtx'):
                    files.append(p)
            if not self.quiet:
                print(f"Parsing {len(files)} EVTX file(s)...")
            for idx, f in enumerate(files):
                try:
                    self._search_evtx_file(
                        f, event_ids, start_time, end_time, position=idx)
                except Exception as e:
                    print(f"Error parsing {f}: {e}")
            
            # Apply deduplication if requested (only for regular mode)
            if 'args' in globals() and getattr(args, 'deduplicate', False):
                self._deduplicate_results()
            
            self._output_results(output_format)
            return

        # Apply log filter to logs list
        if log_filter:
            self.logs = [log_filter]
            if not quiet:
                print(f"Log filter: {log_filter}")

        # Concurrency and progress bars
        use_progress = (progress and tqdm is not None and not quiet)
        results_lists = []

        def run_one(log_name, position=0):
            try:
                if not quiet and not use_progress:
                    print(f"Searching {log_name} log...")
                # Pre-fetch count for progress bar total
                total = 0
                try:
                    total = win32evtlog.GetNumberOfEventLogRecords(
                        win32evtlog.OpenEventLog(None, log_name))
                except Exception:
                    pass
                pbar = None
                if use_progress:
                    pbar = tqdm(
                        total=total, desc=f"{log_name}", position=position, leave=False)
                lst = self._search_log(log_name, event_ids, start_time, end_time, pbar)
                if pbar is not None:
                    pbar.close()
                return lst
            except Exception as e:
                print(f"Error accessing {log_name} log: {e}")
                return []

        if max(1, concurrency) > 1 and len(self.logs) > 1:
            with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
                future_to_log = {}
                for idx, log_name in enumerate(self.logs):
                    future = executor.submit(run_one, log_name, idx)
                    future_to_log[future] = log_name
                for future in as_completed(future_to_log):
                    results_lists.append(future.result())
        else:
            for idx, log_name in enumerate(self.logs):
                results_lists.append(run_one(log_name, idx))

        # Merge results
        for lst in results_lists:
            self.results.extend(lst)

        # Apply deduplication if requested (only for regular mode)
        if 'args' in globals() and getattr(args, 'deduplicate', False):
            self._deduplicate_results()

        self._output_results(output_format)

    def _search_log(self, log_name, event_ids, start_time, end_time, pbar=None):
        """Search a specific event log for the given Event IDs"""
        try:
            # Try to enable security privilege if accessing Security log
            if log_name == "Security":
                self._enable_security_privilege()

            # Open the event log
            hand = win32evtlog.OpenEventLog(None, log_name)

            # Get the number of records
            num_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            if not self.quiet:
                print(f"  Found {num_records} total records in {log_name} log")

            # Read events in reverse chronological order (newest first)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events_checked = 0
            matches_found = 0

            # Read events in batches to avoid memory issues
            while True:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break

                    for event in events:
                        events_checked += 1
                        # Check if event is within our time range
                        event_time = event.TimeGenerated
                        if event_time < start_time or event_time > end_time:
                            # Event is outside our time window
                            if event_time < start_time:
                                # We've gone past our time window; stop processing this batch item
                                continue
                            continue

                        # Check if this is one of our target Event IDs (or if we're in level_all mode)
                        if self.level_all or event.EventID in event_ids:
                            self._process_event(event, log_name)
                            matches_found += 1
                        # Progress hint
                        if pbar is not None:
                            pbar.update(1)
                        elif not self.quiet and events_checked % 200 == 0:
                            target = str(
                                self.max_events) if self.max_events else '∞'
                            print(
                                f"  Progress: checked {events_checked}/{target} events in {log_name}...")
                        # Respect max events limit
                        if self.max_events and events_checked >= self.max_events:
                            break

                    # If we've checked enough events, break
                    if self.max_events and events_checked >= self.max_events:
                        break

                except Exception as e:
                    if "No more data is available" in str(e):
                        break
                    else:
                        raise e

            if pbar is not None:
                # fill remaining if total known and not exceeded
                try:
                    remaining = (pbar.total or 0) - (pbar.n or 0)
                    if remaining and remaining > 0:
                        pbar.update(remaining)
                except Exception:
                    pass
            if not self.quiet and not pbar:
                print(
                    f"  Checked {events_checked} events in {log_name} log, found {matches_found} matches")
            win32evtlog.CloseEventLog(hand)
            return self.results if pbar is None else []

        except Exception as e:
            if "A required privilege is not held by the client" in str(e):
                print(
                    f"  {log_name} log: Access denied - requires elevated privileges")
                print(
                    f"  Note: Security log requires 'SeSecurityPrivilege' even from elevated prompt")
            elif "Access is denied" in str(e):
                print(
                    f"  {log_name} log: Access denied - insufficient privileges")
            else:
                print(f"Error reading {log_name} log: {e}")
            return []

    def _search_evtx_file(self, path, event_ids, start_time, end_time, position=0):
        if EvtxReader is None:
            print("Evtx parsing not available. Install python-evtx.")
            return
        try:
            if not self.quiet:
                print(f"Searching EVTX: {path}")
            with EvtxReader(path) as evtx:
                for record in evtx.records():
                    try:
                        xml = record.xml()
                        root = ET.fromstring(xml)
                        ns = {
                            'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                        # Timestamp
                        ts = root.findtext('.//e:TimeCreated', namespaces=ns)
                        # Fallback: system time in attributes
                        if ts is None:
                            node = root.find(
                                './/e:System/e:TimeCreated', namespaces=ns)
                            if node is not None and 'SystemTime' in node.attrib:
                                ts = node.attrib.get('SystemTime')
                        if ts:
                            try:
                                # normalize to '%Y-%m-%d %H:%M:%S'
                                ts_dt = datetime.fromisoformat(ts.replace(
                                    'Z', '+00:00')).astimezone().replace(tzinfo=None)
                            except Exception:
                                ts_dt = datetime.strptime(
                                    ts.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                        else:
                            ts_dt = datetime.min
                        if ts_dt < start_time or ts_dt > end_time:
                            continue
                        # Channel/Provider/EventID
                        log_name = root.findtext(
                            './/e:System/e:Channel', namespaces=ns) or 'EVTX'
                        provider = root.findtext(
                            './/e:System/e:Provider', namespaces=ns) or 'Unknown'
                        eid_text = root.findtext(
                            './/e:System/e:EventID', namespaces=ns) or '0'
                        try:
                            eid = int(eid_text)
                        except Exception:
                            eid = 0
                        # EventData text (flatten)
                        desc_parts = []
                        for data in root.findall('.//e:EventData/e:Data', namespaces=ns):
                            val = ''.join(data.itertext()).strip()
                            if val:
                                desc_parts.append(val)
                        description = ' | '.join(
                            desc_parts) or 'No description available'

                        dummy_event = type('X', (), {})()
                        dummy_event.EventType = win32con.EVENTLOG_INFORMATION_TYPE
                        dummy_event.SourceName = provider
                        dummy_event.ComputerName = 'offline'
                        dummy_event.EventID = eid
                        dummy_event.TimeGenerated = ts_dt
                        # process via common path
                        self._process_event(dummy_event, log_name)
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error reading EVTX '{path}': {e}")

    def _process_event(self, event, log_name):
        """Process and store event data"""
        try:
            # Get event level
            event_level = self._get_event_level(event.EventType)

            # Apply level filter if specified
            if self.level_filter:
                if isinstance(self.level_filter, (set, list, tuple)):
                    if event_level not in self.level_filter:
                        return
                else:
                    if event_level != self.level_filter:
                        return
                return

            # Get event description
            description = win32evtlogutil.SafeFormatMessage(event, log_name)
            description = description.strip() if description else 'No description available'

            # Apply source filter if specified
            if self.source_filter and self.source_filter.lower() not in event.SourceName.lower():
                return

            # Apply description filter if specified
            if self.description_filter and self.description_filter.lower() not in description.lower():
                return

            # Try to resolve user from event SID if available
            user_name = None
            try:
                if hasattr(event, 'Sid') and event.Sid:
                    name, domain, _ = win32security.LookupAccountSid(
                        None, event.Sid)
                    if domain:
                        user_name = f"{domain}\\{name}"
                    else:
                        user_name = name
            except Exception:
                user_name = None

            # Enrichments parsed from description
            enrich = self._extract_enrichments(description)

            event_data = {
                'timestamp': event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
                'log_name': log_name,
                'event_id': event.EventID,
                'level': event_level,
                'source': event.SourceName,
                'computer': event.ComputerName,
                'user': user_name,
                'description': description,
                'category': self._get_event_category(event.EventID),
                'process': enrich.get('process'),
                'parent': enrich.get('parent'),
                'ip': enrich.get('ip'),
                'port': enrich.get('port'),
                'logon_type': enrich.get('logon_type'),
                'service_name': enrich.get('service_name'),
                'service_path': enrich.get('service_path'),
                'task_name': enrich.get('task_name'),
                'task_command': enrich.get('task_command'),
                'task_arguments': enrich.get('task_arguments')
            }

            # Assign risk score and reasons
            score, reasons = self._score_event(event_data)
            event_data['score'] = score
            event_data['risk_reasons'] = reasons

            # Sigma matching
            if self.sigma_rules:
                matches, tags = self._apply_sigma_rules(event_data)
                if matches:
                    event_data['sigma_matches'] = matches
                    event_data['sigma_tags'] = sorted(list(tags))
                    event_data['score'] = event_data.get(
                        'score', 0) + self.sigma_boost * len(matches)

            # IOC matching
            if self.iocs:
                hits = self._apply_iocs(event_data)
                if hits:
                    event_data['ioc_hits'] = hits
                    event_data['score'] = event_data.get(
                        'score', 0) + self.ioc_boost * len(hits)

            # Apply field filters if provided
            if self._matches_field_filters(event_data) and not self._is_suppressed(event_data) and not self._is_date_excluded(event_data):
                self.results.append(event_data)

        except Exception as e:
            print(f"Error processing event {event.EventID}: {e}")

    def _get_event_level(self, event_type):
        """Convert event type to readable level"""
        level_map = {
            win32con.EVENTLOG_ERROR_TYPE: 'Error',
            win32con.EVENTLOG_WARNING_TYPE: 'Warning',
            win32con.EVENTLOG_INFORMATION_TYPE: 'Information',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'Success Audit',
            win32con.EVENTLOG_AUDIT_FAILURE: 'Failure Audit'
        }
        return level_map.get(event_type, 'Unknown')

    def _get_event_category(self, event_id):
        """Get the threat hunting category for an Event ID"""
        for category, ids in EVENTS.items():
            if event_id in ids:
                return category
        return 'Unknown'

    def _deduplicate_results(self):
        """
        Deduplicate self.results using the same logic as compromise mode.
        Events are considered duplicates if they have the same:
        - Date (extracted from timestamp)
        - Event ID
        - Log name
        - Computer name
        - Description (hashed for comparison)
        """
        if not self.results:
            return
        
        unique_keys = set()
        deduplicated = []
        original_count = len(self.results)
        
        for ev in self.results:
            ts = ev.get('timestamp', '') or ''
            ev_date = ts.split(' ')[0] if ts else ''
            key = (
                ev_date,
                ev.get('event_id'),
                (ev.get('log_name') or ''),
                (ev.get('computer') or ''),
                hash(ev.get('description') or '')
            )
            if key in unique_keys:
                continue
            unique_keys.add(key)
            deduplicated.append(ev)
        
        self.results = deduplicated
        removed_count = original_count - len(deduplicated)
        
        if not self.quiet and removed_count > 0:
            print(f"[Deduplication] Removed {removed_count} duplicate event(s), {len(deduplicated)} unique event(s) remain")

    def _output_results(self, output_format):
        """Output results in the specified format"""
        if not self.results:
            if not self.quiet:
                print("No matching events found.")
            return

        if not self.quiet:
            print(f"\nFound {len(self.results)} matching events:")
            print("=" * 80)

        # Only output results if not in quiet mode
        if not self.quiet:
            if self.matrix_format:
                self._output_matrix()
            elif output_format == 'json':
                print(json.dumps(self.results, indent=2, default=str))
            elif output_format == 'jsonl':
                for e in self.results:
                    print(json.dumps(e, default=str))
            elif output_format == 'csv':
                self._output_csv()
            else:  # text format
                self._output_text()

            # After main output, print triage summaries
            self._output_triage_summaries()
            # Tamper and health checks
            self._output_tamper_health_checks()
            # IOC summary
            self._output_ioc_summary()

    def send_sinks(self, webhook_url=None, hec_url=None, hec_token=None, batch_size=500, use_jsonl=False):
        """Send results to webhook or Splunk HEC endpoints."""
        if not self.results:
            return
        if not webhook_url and not hec_url:
            return
        if requests is None:
            print("Warning: requests not installed; cannot send to sinks.")
            return
        # Batch iterator

        def batches(lst, n):
            for i in range(0, len(lst), n):
                yield lst[i:i+n]

        try:
            if webhook_url:
                for chunk in batches(self.results, max(1, batch_size)):
                    data = '\n'.join(_json.dumps(item, default=str)
                                     for item in chunk) if use_jsonl else _json.dumps(chunk, default=str)
                    headers = {
                        'Content-Type': 'application/x-ndjson' if use_jsonl else 'application/json'}
                    r = requests.post(
                        webhook_url, data=data if use_jsonl else data, headers=headers, timeout=10)
                    if r.status_code >= 300:
                        print(
                            f"Webhook sink POST failed: {r.status_code} {r.text[:120]}")
            if hec_url and hec_token:
                headers = {'Authorization': f'Splunk {hec_token}',
                           'Content-Type': 'application/json'}
                for chunk in batches(self.results, max(1, batch_size)):
                    payload = '\n'.join(_json.dumps(
                        {'event': item}, default=str) for item in chunk)
                    r = requests.post(hec_url, data=payload,
                                      headers=headers, timeout=10)
                    if r.status_code >= 300:
                        print(
                            f"HEC sink POST failed: {r.status_code} {r.text[:120]}")
        except Exception as e:
            print(f"Error sending to sinks: {e}")

    def _output_triage_summaries(self):
        """Print Top findings and heatmaps by category/source."""
        try:
            if not self.results:
                return
            # Top by score
            top = sorted(self.results, key=lambda e: e.get(
                'score', 0), reverse=True)[:10]
            print("\nTop findings (by score):")
            print("-" * 80)
            for i, e in enumerate(top, 1):
                description_clean = e['description'][:80].replace('\n', ' ')
                
                # Add process name if available
                process_info = ""
                if e.get('process'):
                    process_info = f" [{e.get('process')}]"
                
                print(
                    f"{i:>2}. [{e.get('score', 0)}] EID {e['event_id']} {e['log_name']} {e['source']} - {e['timestamp']}{process_info} :: {description_clean}")

            # Heatmaps/counts by category and source
            from collections import Counter
            cat_counts = Counter([e.get('category', 'Unknown')
                                 for e in self.results])
            src_counts = Counter([e.get('source', '') for e in self.results])

            print("\nCounts by category:")
            for cat, cnt in cat_counts.most_common(10):
                print(f"  {cat}: {cnt}")

            print("\nCounts by source:")
            for src, cnt in src_counts.most_common(10):
                print(f"  {src}: {cnt}")
        except Exception as e:
            print(f"Error generating triage summaries: {e}")

    def _output_tamper_health_checks(self):
        """Detect signs of logging tamper or health issues and print a brief report."""
        try:
            if not self.results:
                return
            from collections import defaultdict
            now = datetime.now()
            issues = []

            # Counters
            by_eid = defaultdict(int)
            by_source = defaultdict(int)
            by_log = defaultdict(list)
            future_events = 0

            for e in self.results:
                eid = int(e.get('event_id', 0) or 0)
                src = e.get('source', '') or ''
                by_eid[eid] += 1
                by_source[src] += 1
                by_log[e.get('log_name', '')].append(e)

                # Future timestamp (>5 min ahead)
                try:
                    ts = datetime.strptime(
                        e.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                    if ts - now > timedelta(minutes=5):
                        future_events += 1
                except Exception:
                    pass

            # Known tamper/health indicators
            if by_eid.get(1102, 0):
                issues.append(
                    f"Security log cleared events (1102): {by_eid.get(1102)}")
            if by_eid.get(1101, 0):
                issues.append(
                    f"Audit events dropped (1101): {by_eid.get(1101)}")
            if by_eid.get(1100, 0):
                issues.append(
                    f"Event logging service shutdown (1100): {by_eid.get(1100)}")
            if by_eid.get(4719, 0):
                issues.append(
                    f"System audit policy changed (4719): {by_eid.get(4719)}")

            # Service Control Manager indicates Event Log service stopped (7036 with stopped state)
            scm_stops = 0
            for e in self.results:
                if (e.get('source', '') == 'Service Control Manager' and str(e.get('event_id')) == '7036' and 'stopped' in (e.get('description', '').lower())):
                    scm_stops += 1
            if scm_stops:
                issues.append(
                    f"Windows Event Log service stopped state (7036): {scm_stops}")

            # Time skew
            if future_events:
                issues.append(f"Events in the future (>5m): {future_events}")

            # Gap analysis (>24h) per log
            for log, items in by_log.items():
                try:
                    ordered = sorted(items, key=lambda x: datetime.strptime(
                        x.get('timestamp', ''), '%Y-%m-%d %H:%M:%S'))
                    max_gap = timedelta(0)
                    for a, b in zip(ordered, ordered[1:]):
                        ta = datetime.strptime(
                            a.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                        tb = datetime.strptime(
                            b.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                        gap = tb - ta
                        if gap > max_gap:
                            max_gap = gap
                    if max_gap >= timedelta(hours=24):
                        issues.append(f"Large gap in {log}: {max_gap}")
                except Exception:
                    pass

            if issues:
                print("\nTamper/Health checks:")
                print("-" * 80)
                for msg in issues:
                    print(f"  - {msg}")
            else:
                print("\nTamper/Health checks: No obvious issues detected.")
        except Exception as e:
            print(f"Error in tamper/health checks: {e}")

    def _output_csv(self):
        """Output results in CSV format"""
        if not self.results:
            return

        # CSV header
        headers = ['timestamp', 'log_name', 'event_id', 'level', 'score',
                   'source', 'computer', 'process', 'category', 'description']
        print(','.join(headers))

        # CSV data
        for event in self.results:
            row = []
            for header in headers:
                value = str(event.get(header, '')).replace(
                    ',', ';').replace('\n', ' ').replace('\r', ' ')
                row.append(f'"{value}"')
            print(','.join(row))

    def _output_text(self):
        """Output results in human-readable text format"""
        for i, event in enumerate(self.results, 1):
            # Color based on score
            score = int(event.get('score', 0) or 0)
            color_prefix = ''
            color_suffix = ''
            if Fore and Style:
                if score >= 70:
                    color_prefix = Fore.RED + Style.BRIGHT
                elif score >= 40:
                    color_prefix = Fore.YELLOW + Style.BRIGHT
                elif score > 0:
                    color_prefix = Fore.GREEN
                color_suffix = Style.RESET_ALL

            print(
                f"\n{color_prefix}[{i}] Event ID {event['event_id']} - {event['category']}{color_suffix}")
            print(f"    Time: {event['timestamp']}")
            print(f"    Log: {event['log_name']}")
            print(f"    Level: {event['level']}")
            print(f"    Score: {event.get('score', 0)}")
            print(f"    Source: {event['source']}")
            computer = event.get('computer') or event.get('remote_host') or ''
            print(f"    Computer: {computer}")
            process = event.get('process') or ''
            print(f"    Process: {process}")
            
            # Display service information for service events
            if event.get('service_name'):
                print(f"    Service Name: {event.get('service_name')}")
            if event.get('service_path'):
                print(f"    Service Path: {event.get('service_path')}")
            
            # Display task information for scheduled task events
            if event.get('task_name'):
                print(f"    Task Name: {event.get('task_name')}")
            if event.get('task_command'):
                full_cmd = event.get('task_command')
                if event.get('task_arguments'):
                    full_cmd += f" {event.get('task_arguments')}"
                print(f"    Task Command: {full_cmd}")
            
            if event.get('sigma_matches'):
                print(
                    f"    Sigma: {', '.join(event.get('sigma_matches', []))}")
            if event.get('ioc_hits'):
                print(f"    IOCs: {', '.join(event.get('ioc_hits', []))}")
            print(
                f"    Description: {event['description'][:200]}{'...' if len(event['description']) > 200 else ''}")
            print("-" * 60)

    def _output_matrix(self):
        """Output results in a user-friendly matrix format"""
        if not self.results:
            return

        # Calculate column widths
        max_time = max(len(event['timestamp']) for event in self.results)
        max_log = max(len(event['log_name']) for event in self.results)
        max_level = max(len(event['level']) for event in self.results)
        max_source = max(len(event['source']) for event in self.results)
        max_event_id = max(len(str(event['event_id']))
                           for event in self.results)
        max_score = max(len(str(event.get('score', '')))
                        for event in self.results)

        # Set minimum widths and maximum for description
        time_width = max(19, max_time)  # YYYY-MM-DD HH:MM:SS
        log_width = max(8, max_log)
        level_width = max(11, max_level)
        source_width = min(25, max(max_source, 10))  # Limit source width
        event_id_width = max(8, max_event_id)
        score_width = max(5, max_score, 5)
        desc_width = 50  # Fixed description width

        # Print header
        header = f"{'#':<3} {'Time':<{time_width}} {'Log':<{log_width}} {'Level':<{level_width}} {'Score':<{score_width}} {'Event ID':<{event_id_width}} {'Source':<{source_width}} {'Description':<{desc_width}}"
        print(header)
        print("=" * len(header))

        # Print data rows
        for i, event in enumerate(self.results, 1):
            # Truncate description if too long
            description = event['description'][:desc_width-3] + '...' if len(
                event['description']) > desc_width else event['description']
            description = description.replace(
                '\n', ' ').replace('\r', ' ')  # Remove newlines

            # Truncate source if too long
            source = event['source'][:source_width-3] + \
                '...' if len(event['source']
                             ) > source_width else event['source']

            row = f"{i:<3} {event['timestamp']:<{time_width}} {event['log_name']:<{log_width}} {event['level']:<{level_width}} {str(event.get('score', 0)):<{score_width}} {event['event_id']:<{event_id_width}} {source:<{source_width}} {description:<{desc_width}}"
            print(row)

    def _score_event(self, e):
        """Assign a heuristic risk score and reasons based on event fields.
        Returns (score:int, reasons:list[str]).
        """
        score = 0
        reasons = []
        eid = int(e.get('event_id', 0) or 0)
        level = (e.get('level') or '').lower()
        category = e.get('category') or ''
        process = (e.get('process') or '').lower()
        parent = (e.get('parent') or '').lower()
        source = (e.get('source') or '').lower()
        user = (e.get('user') or '')
        description = (e.get('description') or '').lower()

        # Sensitive events
        high_signal_eids = {1102, 4698, 7045, 4688, 4732, 4728, 4756, 4776}
        if eid in high_signal_eids:
            score += 30
            reasons.append(f"Sensitive EventID {eid}")

        # Privileged context
        has_privileges = False
        if eid == 4672 or 'special privileges' in description:
            score += 25
            reasons.append("Privileged logon context")
            has_privileges = True

        # Category weights
        if 'critical_smoking_gun_indicators' in category:
            score += 30
            reasons.append("Smoking-gun category")
        elif 'credential_access' in category or 'privilege_escalation' in category:
            score += 20
            reasons.append("Cred/priv escalation category")
        elif 'persistence' in category:
            score += 15
            reasons.append("Persistence category")

        # Check if process is in LOLBins IOC list (from lolbins_iocs.csv)
        lolbin_match = False
        if process and hasattr(self, 'lolbins_set') and self.lolbins_set:
            # Extract just the executable name from full path
            process_name = process.split('\\')[-1].strip()
            if process_name in self.lolbins_set or any(lolbin in process for lolbin in self.lolbins_set):
                score += 35  # Higher score for known LOLBins from comprehensive list
                reasons.append(f"LOLBAS binary detected: {process_name}")
                lolbin_match = True
                
                # Additional weight if LOLBin executed with privileges
                if has_privileges:
                    score += 15
                    reasons.append("LOLBin with elevated privileges")

        # Fallback: Check hardcoded common LOLBins if lolbins_iocs.csv not loaded
        if not lolbin_match:
            common_lolbins = ['powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wscript.exe',
                       'cscript.exe', 'certutil.exe', 'bitsadmin.exe', 'schtasks.exe', 'psexec', 'wmic.exe',
                       'msiexec.exe', 'regasm.exe', 'regsvcs.exe', 'installutil.exe', 'msbuild.exe']
            if any(x in process for x in common_lolbins):
                score += 20
                reasons.append("Suspicious LOLBin process")
                
                # Additional weight if executed with privileges
                if has_privileges:
                    score += 10
                    reasons.append("LOLBin with elevated privileges")

        # Check for unsigned/unknown binaries with privileges (suspicious paths)
        if has_privileges and process and eid == 4688:  # Process creation
            suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\', '\\users\\public\\', 
                              '\\programdata\\', '\\downloads\\', '\\desktop\\', '\\documents\\']
            if any(path in process for path in suspicious_paths):
                score += 25
                reasons.append("Privileged execution from suspicious path")
            
            # Check for non-standard executable extensions or no extension
            if process.endswith('.exe') and not any(std_path in process for std_path in ['\\windows\\', '\\program files']):
                score += 15
                reasons.append("Non-standard path privileged execution")
        
        # Office as parent (potential macro/phishing)
        if any(x in parent for x in ['outlook.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe']):
            score += 10
            reasons.append("Office as parent")

        # Level adjustments
        if level in ('error', 'critical'):
            score += 5
            reasons.append("High level severity")

        # Source patterns
        if 'security' in source and eid in {4624, 4648, 4688, 4698, 7045, 1102}:
            score += 5

        # User context
        if user and (user.endswith('\\administrator') or user.lower().endswith('\\admins')):
            score += 5
            reasons.append("Admin user context")

        # Clamp
        if score > 100:
            score = 100
        return score, reasons

    def _apply_iocs(self, e):
        hits = []
        try:
            desc = (e.get('description') or '')
            proc = (e.get('process') or '')
            usr = (e.get('user') or '')
            src = (e.get('source') or '')
            ip = (e.get('ip') or '')
            fields = ' '.join([desc, proc, usr, src, ip]).lower()
            # IPs
            for v in self.iocs.get('ips', set()):
                if v in fields:
                    hits.append(f'ip:{v}')
                    self.ioc_hits_counter[f'ip:{v}'] = self.ioc_hits_counter.get(
                        f'ip:{v}', 0) + 1
            # Domains
            for v in self.iocs.get('domains', set()):
                if v in fields:
                    hits.append(f'domain:{v}')
                    self.ioc_hits_counter[f'domain:{v}'] = self.ioc_hits_counter.get(
                        f'domain:{v}', 0) + 1
            # Hashes (sha1/sha256/md5 substrings)
            for v in self.iocs.get('hashes', set()):
                if v in fields:
                    hits.append(f'hash:{v[:8]}...')
                    self.ioc_hits_counter[f'hash:{v}'] = self.ioc_hits_counter.get(
                        f'hash:{v}', 0) + 1
            # Substrings (command lines/artifacts)
            for v in self.iocs.get('substrings', set()):
                if v in fields:
                    hits.append(f'sub:{v}')
                    self.ioc_hits_counter[f'sub:{v}'] = self.ioc_hits_counter.get(
                        f'sub:{v}', 0) + 1
        except Exception:
            pass
        return hits

    def _output_ioc_summary(self):
        try:
            if not self.ioc_hits_counter:
                return
            print("\nIOC hits summary:")
            print("-" * 80)
            for k, v in sorted(self.ioc_hits_counter.items(), key=lambda x: x[1], reverse=True)[:15]:
                print(f"  {k}: {v}")
        except Exception as e:
            print(f"Error printing IOC summary: {e}")

    def _apply_sigma_rules(self, e):
        """Very lightweight Sigma-like matcher for simple selections.
        Supports keys: event_id, source|contains, description|contains, process|contains, user|contains.
        condition must be 'selection' (single selection dict).
        Returns (matches_titles, tags_set)
        """
        matches = []
        tags = set()
        for rule in self.sigma_rules:
            try:
                detection = rule.get('detection') or {}
                condition = detection.get('condition')
                if condition != 'selection':
                    continue
                sel = detection.get('selection') or {}
                ok = True
                for k, v in sel.items():
                    k_l = k.lower()
                    if k_l == 'eventid' or k_l == 'event_id':
                        try:
                            if int(e.get('event_id', 0)) != int(v):
                                ok = False
                                break
                        except Exception:
                            ok = False
                            break
                    elif '|contains' in k_l:
                        field = k_l.split('|contains')[0]
                        val = (e.get(field) or '')
                        if v is None or str(v).lower() not in str(val).lower():
                            ok = False
                            break
                    else:
                        # equality on simple mapped fields
                        val = (e.get(k_l) or '')
                        if str(val).lower() != str(v).lower():
                            ok = False
                            break
                if ok:
                    matches.append(rule.get('title')
                                   or rule.get('id') or 'sigma_rule')
                    for t in rule.get('tags', []) or []:
                        tags.add(t)
            except Exception:
                continue
        return matches, tags

    def _extract_enrichments(self, description):
        """Extract common fields from description using heuristics/regex."""
        fields = {}
        if not description:
            return fields
        try:
            # Process/Image
            m = re.search(r"New Process Name:\s*(.+)", description)
            if not m:
                m = re.search(r"Process Name:\s*(.+)", description)
            if not m:
                m = re.search(r"Image:\s*(.+)", description)
            if m:
                fields['process'] = m.group(1).strip()

            # Parent
            m = re.search(r"Parent Process Name:\s*(.+)", description)
            if not m:
                m = re.search(r"Parent Image:\s*(.+)", description)
            if m:
                fields['parent'] = m.group(1).strip()

            # Logon Type
            m = re.search(r"Logon Type:\s*(\d+)", description)
            if m:
                fields['logon_type'] = m.group(1)

            # IP (IPv4/IPv6) - Source Network Address
            m = re.search(
                r"Source Network Address:\s*([0-9a-fA-F:\.]+)", description)
            if m:
                fields['ip'] = m.group(1).strip()

            # Port
            m = re.search(r"Source Port:\s*(\d+)", description)
            if m:
                fields['port'] = m.group(1)
            
            # Service Name (Event ID 4697, 7045, 7036, etc.)
            m = re.search(r"Service Name:\s*(.+?)(?:\r?\n|$)", description)
            if m:
                fields['service_name'] = m.group(1).strip()
            
            # Service File Name / Service Path (Event ID 4697, 7045)
            m = re.search(r"Service File Name:\s*(.+?)(?:\r?\n|$)", description)
            if not m:
                m = re.search(r"Image Path:\s*(.+?)(?:\r?\n|$)", description)
            if m:
                fields['service_path'] = m.group(1).strip()
            
            # Scheduled Task Name (Event ID 4698, 4699, 4700, 4701, 4702, 106, 140, 141, 200, 201)
            m = re.search(r"Task Name:\s*(.+?)(?:\r?\n|$)", description)
            if m:
                fields['task_name'] = m.group(1).strip()
            
            # Scheduled Task Command/Action (Event ID 4698, 4699, 4700, 4701, 4702)
            # Extract from XML-like content in task registration events
            m = re.search(r"<Command>(.+?)</Command>", description, re.IGNORECASE)
            if m:
                fields['task_command'] = m.group(1).strip()
            
            # Alternative: Look for Action/Arguments in task description
            m = re.search(r"<Actions.*?<Exec>.*?<Command>(.+?)</Command>", description, re.IGNORECASE | re.DOTALL)
            if m and not fields.get('task_command'):
                fields['task_command'] = m.group(1).strip()
            
            # Task Arguments
            m = re.search(r"<Arguments>(.+?)</Arguments>", description, re.IGNORECASE)
            if m:
                fields['task_arguments'] = m.group(1).strip()
                
        except Exception:
            pass
        return fields

    def _matches_field_filters(self, event_data):
        """Evaluate regex-based field filters with AND/OR and optional negation."""
        if not self.field_filters:
            return True
        results = []
        for key, pattern in self.field_filters.items():
            if not pattern:
                # Skip unset/empty patterns
                continue
            try:
                value = event_data.get(key)
                if value is None:
                    results.append(False)
                    continue
                if re.search(pattern, str(value), flags=re.IGNORECASE):
                    results.append(True)
                else:
                    results.append(False)
            except re.error:
                results.append(False)
        # If no valid patterns were supplied, treat as pass-through
        if not results:
            return True
        match = all(results) if self.bool_logic == 'and' else any(results)
        return (not match) if self.negate else match

    def _is_suppressed(self, event_data):
        """Return True if event matches allowlist or suppress rules."""
        # Allowlist (suppression) via file
        try:
            al = self.allowlist
            if al:
                # Event IDs
                if 'event_ids' in al and event_data.get('event_id') in set(al.get('event_ids', [])):
                    return True
                # Sources exact
                if 'sources' in al and event_data.get('source') in set(al.get('sources', [])):
                    return True
                # Users exact
                if 'users' in al and event_data.get('user') in set(al.get('users', [])):
                    return True
                # Process regex
                for pat in al.get('process_regex', []) or []:
                    try:
                        if event_data.get('process') and re.search(pat, event_data.get('process'), re.IGNORECASE):
                            return True
                    except re.error:
                        continue
                # Description regex
                for pat in al.get('description_regex', []) or []:
                    try:
                        if event_data.get('description') and re.search(pat, event_data.get('description'), re.IGNORECASE):
                            return True
                    except re.error:
                        continue
        except Exception:
            pass

        # Ad-hoc suppress rules from CLI: format like 'source:Security-SPP' or 'eid:4688'
        try:
            for rule in self.suppress_rules or []:
                if not rule or ':' not in rule:
                    continue
                key, value = rule.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                if key in ('eid', 'event_id'):
                    try:
                        if int(event_data.get('event_id')) == int(value):
                            return True
                    except Exception:
                        continue
                elif key == 'source':
                    if str(event_data.get('source', '')).lower() == value.lower():
                        return True
                elif key == 'user':
                    if str(event_data.get('user', '')).lower() == value.lower():
                        return True
                elif key == 'process':
                    try:
                        if event_data.get('process') and re.search(value, event_data.get('process'), re.IGNORECASE):
                            return True
                    except re.error:
                        continue
                elif key in ('desc', 'description'):
                    try:
                        if event_data.get('description') and re.search(value, event_data.get('description'), re.IGNORECASE):
                            return True
                    except re.error:
                        continue
        except Exception:
            pass

        return False

    def _is_date_excluded(self, event_data):
        """Return True if event's date matches any excluded dates."""
        if not self.exclude_dates:
            return False
        
        try:
            timestamp = event_data.get('timestamp', '')
            if timestamp:
                # Extract date from timestamp (format: 'YYYY-MM-DD HH:MM:SS')
                event_date = timestamp.split(' ')[0]
                return event_date in self.exclude_dates
        except Exception:
            pass
        
        return False

    def check_log_availability(self):
        """Check how far back each log has data available"""
        print("Checking log availability...")
        print("=" * 80)

        for log_name in self.logs:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)

                # Get oldest and newest events
                flags_oldest = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                flags_newest = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                # Read oldest event
                oldest_events = win32evtlog.ReadEventLog(hand, flags_oldest, 0)
                oldest_time = None
                if oldest_events:
                    oldest_time = oldest_events[0].TimeGenerated

                # Read newest event
                newest_events = win32evtlog.ReadEventLog(hand, flags_newest, 0)
                newest_time = None
                if newest_events:
                    newest_time = newest_events[0].TimeGenerated

                win32evtlog.CloseEventLog(hand)

                if oldest_time and newest_time:
                    time_span = newest_time - oldest_time
                    days = time_span.days
                    hours = time_span.seconds // 3600

                    print(f"{log_name} Log:")
                    print(
                        f"  Oldest event: {oldest_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(
                        f"  Newest event: {newest_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"  Available span: {days} days, {hours} hours")

                    # Calculate months and years
                    months = days // 30
                    years = days // 365
                    if years > 0:
                        print(
                            f"  Approximate: {years} year{'s' if years > 1 else ''}, {months % 12} month{'s' if (months % 12) != 1 else ''}")
                    elif months > 0:
                        print(
                            f"  Approximate: {months} month{'s' if months > 1 else ''}")
                    print()
                else:
                    print(f"{log_name} Log: No events found or unable to read")
                    print()

            except Exception as e:
                print(f"{log_name} Log: Error accessing log - {e}")
                print()

        # Calculate overall availability
        print("Summary:")
        print("-" * 40)
        all_oldest = []
        all_newest = []

        for log_name in self.logs:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags_oldest = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                flags_newest = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                oldest_events = win32evtlog.ReadEventLog(hand, flags_oldest, 0)
                newest_events = win32evtlog.ReadEventLog(hand, flags_newest, 0)

                if oldest_events:
                    all_oldest.append(oldest_events[0].TimeGenerated)
                if newest_events:
                    all_newest.append(newest_events[0].TimeGenerated)

                win32evtlog.CloseEventLog(hand)
            except:
                continue

        if all_oldest and all_newest:
            overall_oldest = min(all_oldest)
            overall_newest = max(all_newest)
            overall_span = overall_newest - overall_oldest

            print(f"Overall log availability:")
            print(f"  From: {overall_oldest.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  To:   {overall_newest.strftime('%Y-%m-%d %H:%M:%S')}")
            print(
                f"  Span: {overall_span.days} days ({overall_span.days // 30} months, {overall_span.days // 365} years)")

            # Show what time ranges are searchable
            print(f"\nSearchable time ranges:")
            print(f"  Last 24 hours: [OK]")
            print(
                f"  Last 7 days: {'[OK]' if overall_span.days >= 7 else '[NO]'}")
            print(
                f"  Last 30 days: {'[OK]' if overall_span.days >= 30 else '[NO]'}")
            print(
                f"  Last 3 months: {'[OK]' if overall_span.days >= 90 else '[NO]'}")
            print(
                f"  Last 6 months: {'[OK]' if overall_span.days >= 180 else '[NO]'}")
            print(
                f"  Last year: {'[OK]' if overall_span.days >= 365 else '[NO]'}")
            print(
                f"  Full history: {'[OK]' if overall_span.days >= 365 else '[NO]'} ({overall_span.days} days available)")

    def configure_log_retention(self, days=365, max_size_mb=1024, retention_policy='overwrite_as_needed', force=False):
        """
        Configure Windows Event Log retention policies to preserve logs longer

        Args:
            days (int): Number of days to retain logs (default: 365)
            max_size_mb (int): Maximum log size in MB (default: 1024)
            retention_policy (str): 'overwrite_as_needed', 'archive_when_full', or 'never_overwrite'
        """
        print("Configuring Windows Event Log retention policies...")
        print("=" * 80)
        print(f"Target retention: {days} days")
        print(f"Max log size: {max_size_mb} MB")
        print(f"Retention policy: {retention_policy}")
        print()

        # Check if running as administrator
        if not force and not self._is_admin():
            print("WARNING: Administrator privileges not detected.")
            print("Attempting to configure anyway (some systems may still work)...")
            print(
                "If this fails, try running from an elevated PowerShell or Command Prompt.")
            print("Or use --force to bypass this check.")
            print()

        # Registry paths for event log settings
        log_configs = {
            'Application': r'SYSTEM\CurrentControlSet\Services\Eventlog\Application',
            'Security': r'SYSTEM\CurrentControlSet\Services\Eventlog\Security',
            'Setup': r'SYSTEM\CurrentControlSet\Services\Eventlog\Setup',
            'System': r'SYSTEM\CurrentControlSet\Services\Eventlog\System'
        }

        # Retention policy mapping
        retention_map = {
            # Overwrite events as needed (oldest first)
            'overwrite_as_needed': 0,
            'archive_when_full': 1,        # Archive the log when full, do not overwrite events
            # Never overwrite events (clear logs manually)
            'never_overwrite': 2
        }

        retention_value = retention_map.get(retention_policy, 0)

        success_count = 0
        total_count = len(log_configs)

        for log_name, reg_path in log_configs.items():
            try:
                print(f"Configuring {log_name} log...")

                # Open registry key
                key = win32api.RegOpenKeyEx(
                    win32con.HKEY_LOCAL_MACHINE,
                    reg_path,
                    0,
                    win32con.KEY_SET_VALUE
                )

                # Set retention period (in days)
                win32api.RegSetValueEx(
                    key, "Retention", 0, win32con.REG_DWORD, days)

                # Set maximum log size (in bytes)
                max_size_bytes = max_size_mb * 1024 * 1024
                win32api.RegSetValueEx(
                    key, "MaxSize", 0, win32con.REG_DWORD, max_size_bytes)

                # Set retention policy
                win32api.RegSetValueEx(
                    key, "RetentionPolicy", 0, win32con.REG_DWORD, retention_value)

                # Enable auto-backup (optional)
                win32api.RegSetValueEx(
                    key, "AutoBackupLogFiles", 0, win32con.REG_DWORD, 1)

                win32api.RegCloseKey(key)

                print(f"  [OK] {log_name} log configured successfully")
                success_count += 1

            except Exception as e:
                print(f"  [FAILED] Failed to configure {log_name} log: {e}")

        print()
        print(f"Configuration Summary:")
        print(f"  Successfully configured: {success_count}/{total_count} logs")

        if success_count > 0:
            print()
            print("IMPORTANT NOTES:")
            print("1. Changes may require a system restart to take full effect")
            print("2. Consider restarting the Windows Event Log service:")
            print("   net stop eventlog && net start eventlog")
            print("3. Monitor disk space as larger retention will use more storage")
            print("4. Security log may have additional restrictions")

            return True
        else:
            print("No logs were successfully configured.")
            return False

    def _is_admin(self):
        """Check if the current process is running with administrator privileges"""
        try:
            # Method 1: Check if user is admin
            if win32security.IsUserAnAdmin():
                return True

            # Method 2: Try to open a registry key that requires admin privileges
            try:
                key = win32api.RegOpenKeyEx(
                    win32con.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Services\Eventlog\Security',
                    0,
                    win32con.KEY_SET_VALUE
                )
                win32api.RegCloseKey(key)
                return True
            except:
                pass

            # Method 3: Check process token
            try:
                token = win32security.OpenProcessToken(
                    win32api.GetCurrentProcess(),
                    win32security.TOKEN_QUERY
                )
                groups = win32security.GetTokenInformation(
                    token, win32security.TokenGroups)
                win32api.CloseHandle(token)

                # Check if we're in the Administrators group
                admin_sid = win32security.CreateWellKnownSid(
                    win32security.WinBuiltinAdministratorsSid)
                for group in groups[0]:
                    if win32security.EqualSid(group[0], admin_sid):
                        return True
            except:
                pass

            return False
        except:
            return False

    def _enable_security_privilege(self):
        """Try to enable SeSecurityPrivilege for reading Security log"""
        try:
            # Get current process token
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )

            # Look up the privilege
            privilege = win32security.LookupPrivilegeValue(
                None, "SeSecurityPrivilege")

            # Enable the privilege
            win32security.AdjustTokenPrivileges(
                token,
                False,
                [(privilege, win32security.SE_PRIVILEGE_ENABLED)]
            )

            win32api.CloseHandle(token)
            return True
        except Exception as e:
            print(f"Could not enable SeSecurityPrivilege: {e}")
            return False

    def show_current_retention_settings(self):
        """Display current log retention settings"""
        print("Current Windows Event Log retention settings:")
        print("=" * 80)

        log_configs = {
            'Application': r'SYSTEM\CurrentControlSet\Services\Eventlog\Application',
            'Security': r'SYSTEM\CurrentControlSet\Services\Eventlog\Security',
            'Setup': r'SYSTEM\CurrentControlSet\Services\Eventlog\Setup',
            'System': r'SYSTEM\CurrentControlSet\Services\Eventlog\System'
        }

        retention_policies = {
            0: 'Overwrite as needed (oldest first)',
            1: 'Archive when full (do not overwrite)',
            2: 'Never overwrite (clear manually)'
        }

        for log_name, reg_path in log_configs.items():
            try:
                print(f"\n{log_name} Log:")

                # Open registry key
                key = win32api.RegOpenKeyEx(
                    win32con.HKEY_LOCAL_MACHINE,
                    reg_path,
                    0,
                    win32con.KEY_READ
                )

                # Read retention settings
                try:
                    retention_days, _ = win32api.RegQueryValueEx(
                        key, "Retention")
                    print(f"  Retention period: {retention_days} days")
                except:
                    print(f"  Retention period: Not set (default)")

                try:
                    max_size_bytes, _ = win32api.RegQueryValueEx(
                        key, "MaxSize")
                    max_size_mb = max_size_bytes // (1024 * 1024)
                    print(f"  Max size: {max_size_mb} MB")
                except:
                    print(f"  Max size: Not set (default)")

                try:
                    retention_policy, _ = win32api.RegQueryValueEx(
                        key, "RetentionPolicy")
                    policy_desc = retention_policies.get(
                        retention_policy, f"Unknown ({retention_policy})")
                    print(f"  Retention policy: {policy_desc}")
                except:
                    print(f"  Retention policy: Not set (default)")

                try:
                    auto_backup, _ = win32api.RegQueryValueEx(
                        key, "AutoBackupLogFiles")
                    print(
                        f"  Auto backup: {'Enabled' if auto_backup else 'Disabled'}")
                except:
                    print(f"  Auto backup: Not set (default)")

                win32api.RegCloseKey(key)

            except Exception as e:
                print(f"  Error reading {log_name} settings: {e}")

        print()
        print("Note: Some settings may not be visible without administrator privileges")

    def open_event_viewer(self):
        """Open Windows Event Viewer"""
        try:
            print("Opening Windows Event Viewer...")
            # Use start command to open the MMC file
            subprocess.run(['cmd', '/c', 'start', 'eventvwr.msc'], check=True)
            print("Event Viewer opened successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to open Event Viewer: {e}")
            return False
        except FileNotFoundError:
            print("Event Viewer not found. Trying alternative method...")
            try:
                # Try using mmc directly
                subprocess.run(['mmc', 'eventvwr.msc'], check=True)
                print("Event Viewer opened successfully.")
                return True
            except:
                print("Failed to open Event Viewer with alternative method.")
                return False

    def open_log_directory(self):
        """Open Windows Event Log directory"""
        try:
            print("Opening Windows Event Log directory...")

            # List of possible log directory locations
            possible_dirs = [
                r"C:\Windows\System32\winevt\Logs",
                r"C:\Windows\Logs",
                r"C:\Windows\System32\LogFiles",
                r"C:\ProgramData\Microsoft\Windows\WER"
            ]

            for log_dir in possible_dirs:
                if os.path.exists(log_dir):
                    # Use cmd /c start to avoid opening twice
                    subprocess.run(
                        ['cmd', '/c', 'start', 'explorer', log_dir], check=True)
                    print(f"Event Log directory opened: {log_dir}")
                    return True

            # If no directory found, open Windows directory
            print("No specific Event Log directory found. Opening Windows directory...")
            subprocess.run(['cmd', '/c', 'start', 'explorer',
                           r"C:\Windows"], check=True)
            print("Windows directory opened. Look for 'Logs' or 'System32' folders.")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to open log directory: {e}")
            return False
        except Exception as e:
            print(f"Error opening log directory: {e}")
            return False

    def configure_log_retention_powershell(self, days=365, max_size_mb=1024, retention_policy='overwrite_as_needed'):
        """
        Configure Windows Event Log retention using PowerShell with dynamic parameters
        """
        print("Configuring Windows Event Log retention using PowerShell...")
        print("=" * 80)
        print(f"Target retention: {days} days")
        print(f"Max log size: {max_size_mb} MB")
        print(f"Retention policy: {retention_policy}")
        print()

        # Validate max size (Windows registry DWORD limit is ~4GB)
        # Use conservative limit to avoid overflow issues
        # Maximum 32-bit signed integer (safer limit)
        max_dword_value = 2147483647
        max_size_bytes = max_size_mb * 1024 * 1024

        if max_size_bytes > max_dword_value:
            print(
                f"WARNING: Requested size {max_size_mb} MB ({max_size_bytes} bytes) exceeds Windows registry limit.")
            print(f"Maximum allowed size: {max_dword_value // (1024*1024)} MB")
            print(f"Adjusting to maximum allowed size...")
            max_size_mb = max_dword_value // (1024 * 1024)
            max_size_bytes = max_dword_value
            print(f"Using adjusted size: {max_size_mb} MB")

        # Create PowerShell script with dynamic parameters
        ps_script = f'''
# PowerShell script to configure Windows Event Log retention
param(
    [int]$Days = {days},
    [int]$MaxSizeMB = {max_size_mb},
    [string]$RetentionPolicy = "{retention_policy}"
)

Write-Host "Configuring Windows Event Log retention policies..." -ForegroundColor Green
Write-Host "Target retention: $Days days" -ForegroundColor Yellow
Write-Host "Max log size: $MaxSizeMB MB" -ForegroundColor Yellow
Write-Host "Retention policy: $RetentionPolicy" -ForegroundColor Yellow
Write-Host ""

# Retention policy mapping
$retentionMap = @{{
    "overwrite_as_needed" = 0
    "archive_when_full" = 1
    "never_overwrite" = 2
}}

$retentionValue = $retentionMap[$RetentionPolicy]

# Log configurations
$logConfigs = @{{
    "Application" = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application"
    "Security" = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security"
    "Setup" = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Setup"
    "System" = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\System"
}}

$successCount = 0
$totalCount = $logConfigs.Count

foreach ($logName in $logConfigs.Keys) {{
    $regPath = $logConfigs[$logName]

    try {{
        Write-Host "Configuring $logName log..." -ForegroundColor Cyan

        # Check if registry path exists
        if (Test-Path $regPath) {{
            # Set retention period (in days)
            Set-ItemProperty -Path $regPath -Name "Retention" -Value $Days -Type DWord

            # Set maximum log size (in bytes) - use UInt32 to handle large values
            $maxSizeBytes = [UInt32]($MaxSizeMB * 1024 * 1024)
            Set-ItemProperty -Path $regPath -Name "MaxSize" -Value $maxSizeBytes -Type DWord

            # Set retention policy
            Set-ItemProperty -Path $regPath -Name "RetentionPolicy" -Value $retentionValue -Type DWord

            # Enable auto-backup
            Set-ItemProperty -Path $regPath -Name "AutoBackupLogFiles" -Value 1 -Type DWord

            Write-Host "  [OK] $logName log configured successfully" -ForegroundColor Green
            $successCount++
        }} else {{
            Write-Host "  [SKIP] $logName log registry path not found" -ForegroundColor Yellow
        }}
    }}
    catch {{
        Write-Host "  [FAILED] Failed to configure $logName log: $($_.Exception.Message)" -ForegroundColor Red
    }}
}}

Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor Green
Write-Host "  Successfully configured: $successCount/$totalCount logs" -ForegroundColor Yellow

if ($successCount -gt 0) {{
    Write-Host ""
    Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "1. Changes may require a system restart to take full effect" -ForegroundColor White
    Write-Host "2. Consider restarting the Windows Event Log service:" -ForegroundColor White
    Write-Host "   net stop eventlog && net start eventlog" -ForegroundColor Gray
    Write-Host "3. Monitor disk space as larger retention will use more storage" -ForegroundColor White
    Write-Host "4. Security log may have additional restrictions" -ForegroundColor White
}}
'''

        try:
            # Create temporary PowerShell script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                f.write(ps_script)
                temp_script = f.name

            # Execute PowerShell script with execution policy bypass
            cmd = [
                'powershell.exe',
                '-ExecutionPolicy', 'Bypass',
                '-File', temp_script
            ]

            print("Executing PowerShell script...")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60)

            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print("PowerShell Errors:", result.stderr)

            # Clean up temporary file
            try:
                os.unlink(temp_script)
            except:
                pass

            return result.returncode == 0

        except subprocess.TimeoutExpired:
            print("PowerShell script timed out")
            return False
        except Exception as e:
            print(f"Error executing PowerShell script: {e}")
            return False

    def configure_log_retention_registry(self, days=365, max_size_mb=1024, retention_policy='overwrite_as_needed'):
        """
        Configure Windows Event Log retention using reg.exe commands
        """
        print("Configuring Windows Event Log retention using registry commands...")
        print("=" * 80)
        print(f"Target retention: {days} days")
        print(f"Max log size: {max_size_mb} MB")
        print(f"Retention policy: {retention_policy}")
        print()

        # Retention policy mapping
        retention_map = {
            'overwrite_as_needed': 0,
            'archive_when_full': 1,
            'never_overwrite': 2
        }

        retention_value = retention_map.get(retention_policy, 0)

        # Validate max size (Windows registry DWORD limit is ~4GB)
        # Use conservative limit to avoid overflow issues
        # Maximum 32-bit signed integer (safer limit)
        max_dword_value = 2147483647
        max_size_bytes = max_size_mb * 1024 * 1024

        if max_size_bytes > max_dword_value:
            print(
                f"WARNING: Requested size {max_size_mb} MB ({max_size_bytes} bytes) exceeds Windows registry limit.")
            print(f"Maximum allowed size: {max_dword_value // (1024*1024)} MB")
            print(f"Adjusting to maximum allowed size...")
            max_size_mb = max_dword_value // (1024 * 1024)
            max_size_bytes = max_dword_value
            print(f"Using adjusted size: {max_size_mb} MB")

        # Registry paths
        log_configs = {
            'Application': r'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application',
            'Security': r'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security',
            'Setup': r'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Setup',
            'System': r'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System'
        }

        success_count = 0
        total_count = len(log_configs)

        for log_name, reg_path in log_configs.items():
            try:
                print(f"Configuring {log_name} log...")

                # Set retention period
                cmd1 = ['reg', 'add', reg_path, '/v', 'Retention',
                        '/t', 'REG_DWORD', '/d', str(days), '/f']
                result1 = subprocess.run(cmd1, capture_output=True, text=True)

                # Set max size
                cmd2 = ['reg', 'add', reg_path, '/v', 'MaxSize', '/t',
                        'REG_DWORD', '/d', str(max_size_bytes), '/f']
                result2 = subprocess.run(cmd2, capture_output=True, text=True)

                # Set retention policy
                cmd3 = ['reg', 'add', reg_path, '/v', 'RetentionPolicy',
                        '/t', 'REG_DWORD', '/d', str(retention_value), '/f']
                result3 = subprocess.run(cmd3, capture_output=True, text=True)

                # Enable auto-backup
                cmd4 = ['reg', 'add', reg_path, '/v',
                        'AutoBackupLogFiles', '/t', 'REG_DWORD', '/d', '1', '/f']
                result4 = subprocess.run(cmd4, capture_output=True, text=True)

                # Check if all commands succeeded
                if all([result1.returncode == 0, result2.returncode == 0,
                       result3.returncode == 0, result4.returncode == 0]):
                    print(f"  [OK] {log_name} log configured successfully")
                    success_count += 1
                else:
                    print(f"  [FAILED] Failed to configure {log_name} log")
                    if result1.stderr:
                        print(f"    Error: {result1.stderr.strip()}")

            except Exception as e:
                print(f"  [FAILED] Failed to configure {log_name} log: {e}")

        print()
        print(f"Configuration Summary:")
        print(f"  Successfully configured: {success_count}/{total_count} logs")

        if success_count > 0:
            print()
            print("IMPORTANT NOTES:")
            print("1. Changes may require a system restart to take full effect")
            print("2. Consider restarting the Windows Event Log service:")
            print("   net stop eventlog && net start eventlog")
            print("3. Monitor disk space as larger retention will use more storage")
            print("4. Security log may have additional restrictions")

            return True
        else:
            print("No logs were successfully configured.")
            return False


def search_threat_indicators(hours_back=24, output_format='text', specific_categories=None, level_filter=None, level_all=False, 
                             matrix_format=False, log_filter=None, source_filter=None, description_filter=None, quiet=False, field_filters=None, bool_logic='and', negate=False, all_events=False, explicit_event_ids=None, specific_date=None, from_date=None, to_date=None):
    """
    Search for threat hunting Event IDs in Windows logs

    Args:
        hours_back (int): Hours to look back (default: 24)
        output_format (str): 'json', 'text', or 'csv'
        specific_categories (list): Specific threat categories to search for
        level_filter (str): Filter events by level (Error, Warning, Information, etc.)
        level_all (bool): If True, search for all events of the specified level, ignoring Event ID filter
        matrix_format (bool): If True, display results in matrix format
        log_filter (str): Filter results to specific log type
        source_filter (str): Filter results where source contains this string
        description_filter (str): Filter results where description contains this string
    """
    # Load Sigma rules if requested
    sigma_rules = []
    if getattr(args, 'sigma_dir', None):
        if yaml is None:
            print("Warning: PyYAML not installed; cannot load Sigma rules.")
        else:
            try:
                for root, _, files in os.walk(args.sigma_dir):
                    for f in files:
                        if f.lower().endswith(('.yml', '.yaml')):
                            path = os.path.join(root, f)
                            with open(path, 'r', encoding='utf-8') as fh:
                                rule = yaml.safe_load(fh)
                                if isinstance(rule, dict):
                                    sigma_rules.append(rule)
                print(
                    f"Loaded {len(sigma_rules)} Sigma rule(s) from {args.sigma_dir}")
            except Exception as e:
                print(f"Warning: failed to load Sigma rules: {e}")

    # Load IOCs if provided
    iocs = {'ips': set(), 'domains': set(),
            'hashes': set(), 'substrings': set()}
    lolbins_set = set()  # Separate set for LOLBins executables
    
    try:
        if getattr(args, 'ioc', None):
            fmt = getattr(args, 'ioc_format', 'csv')
            if fmt == 'csv':
                import csv
                with open(args.ioc, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        typ = (row.get('type') or '').strip().lower()
                        val = (row.get('value') or '').strip().lower()
                        if not typ or not val:
                            continue
                        if typ in ('ip', 'ips'):
                            iocs['ips'].add(val)
                        elif typ in ('domain', 'domains'):
                            iocs['domains'].add(val)
                        elif typ in ('hash', 'md5', 'sha1', 'sha256'):
                            iocs['hashes'].add(val)
                        elif typ in ('lolbin', 'lolbins', 'lolbas'):
                            # Extract just executable names for LOLBins
                            # Handle both full paths and just names
                            if '\\' in val or '/' in val:
                                lolbin_name = val.split('\\')[-1].split('/')[-1]
                            else:
                                lolbin_name = val
                            lolbins_set.add(lolbin_name)
                            # Also add to substrings for description matching
                            iocs['substrings'].add(val)
                        else:
                            iocs['substrings'].add(val)
            elif fmt == 'txt':
                with open(args.ioc, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        val = line.strip().lower()
                        if not val or val.startswith('#'):
                            continue
                        # naive classification
                        if any(c.isalpha() for c in val) and '.' in val and not any(ch in val for ch in [' ', '\t']):
                            iocs['domains'].add(val)
                        elif all(ch in '0123456789abcdef' for ch in val) and len(val) in (32, 40, 64):
                            iocs['hashes'].add(val)
                        elif all(ch in '0123456789.:abcdef' for ch in val) and any(ch in val for ch in '.:'):
                            iocs['ips'].add(val)
                        else:
                            iocs['substrings'].add(val)
            elif fmt == 'stix':
                with open(args.ioc, 'r', encoding='utf-8', errors='ignore') as f:
                    stix = json.load(f)
                objs = stix.get('objects', []) if isinstance(
                    stix, dict) else []
                for o in objs:
                    ind = o.get('indicator') or o if isinstance(
                        o, dict) else {}
                    patt = ind.get('pattern') or ''
                    val = o.get('name') or ''
                    blob = f"{patt} {val}".lower()
                    # naive extraction
                    for token in blob.replace("'", ' ').replace('"', ' ').split():
                        t = token.strip()
                        if not t:
                            continue
                        if any(c.isalpha() for c in t) and '.' in t and not any(ch in t for ch in [' ', '\t']):
                            iocs['domains'].add(t)
                        elif all(ch in '0123456789abcdef' for ch in t) and len(t) in (32, 40, 64):
                            iocs['hashes'].add(t)
                        elif all(ch in '0123456789.:abcdef' for ch in t) and any(ch in t for ch in '.:'):
                            iocs['ips'].add(t)
            print(
                f"Loaded IOCs: ips={len(iocs['ips'])}, domains={len(iocs['domains'])}, hashes={len(iocs['hashes'])}, subs={len(iocs['substrings'])}")
    except Exception as e:
        print(f"Warning: failed to load IOCs: {e}")
    
    # Auto-load lolbins_iocs.csv if it exists (for enhanced scoring and detection)
    lolbins_csv_path = os.path.join('ioc', 'lolbins_iocs.csv')
    if os.path.exists(lolbins_csv_path) and not getattr(args, 'ioc', None):
        try:
            import csv
            with open(lolbins_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    typ = (row.get('type') or '').strip().lower()
                    val = (row.get('value') or '').strip().lower()
                    if typ in ('lolbin', 'lolbins', 'lolbas', 'substring') and val:
                        # Extract executable name
                        if '\\' in val or '/' in val:
                            lolbin_name = val.split('\\')[-1].split('/')[-1]
                        else:
                            lolbin_name = val
                        if lolbin_name.endswith('.exe'):
                            lolbins_set.add(lolbin_name)
            if lolbins_set:
                print(f"Auto-loaded {len(lolbins_set)} LOLBins from {lolbins_csv_path}")
        except Exception as e:
            pass  # Silently fail if auto-load doesn't work

    searcher = WindowsEventLogSearcher(sigma_rules=sigma_rules, sigma_boost=getattr(
        args, 'sigma_boost', 10), iocs=iocs, ioc_boost=getattr(args, 'ioc_boost', 5),
        exclude_dates=getattr(args, 'exclude_dates', None), lolbins_set=lolbins_set)

    if all_events:
        event_ids = []
        level_all = True
        level_filter = None
    elif level_all:
        # In level_all mode, we don't need specific Event IDs
        event_ids = []
    elif explicit_event_ids:
        # User-specified explicit event IDs
        event_ids = list(set(int(e) for e in explicit_event_ids))
    elif specific_categories:
        # Search only specific categories
        event_ids = []
        for category in specific_categories:
            if category in EVENTS:
                event_ids.extend(EVENTS[category])
        event_ids = list(set(event_ids))  # Remove duplicates
    else:
        # Search all Event IDs
        event_ids = ALL_EVENT_IDS

    # If --all-events, ignore event_ids and level filtering later
    if getattr(sys.modules.get(__name__), 'args', None) and getattr(args, 'all_events', False):
        event_ids = []

    # Forward global args if present for concurrency/progress
    conc = 1
    prog = False
    try:
        if 'args' in globals():
            conc = getattr(args, 'concurrency', 1)
            prog = getattr(args, 'progress', False)
    except Exception:
        pass
    # Load allowlist JSON if provided
    allowlist_obj = {}
    try:
        if getattr(args, 'allowlist', None):
            with open(args.allowlist, 'r', encoding='utf-8') as f:
                allowlist_obj = json.load(f)
    except Exception as e:
        print(f"Warning: failed to load allowlist file: {e}")
        allowlist_obj = {}

    searcher.search_event_ids(
        event_ids,
        hours_back,
        output_format,
        level_filter,
        level_all,
        matrix_format,
        log_filter,
        source_filter,
        description_filter,
        quiet,
        field_filters,
        bool_logic,
        negate,
        max_events=getattr(args, 'max_events', 0),
        concurrency=conc,
        progress=prog,
        allowlist=allowlist_obj,
        suppress_rules=getattr(args, 'suppress', None),
        specific_date=specific_date,
        from_date=getattr(args, 'from_date', None),
        to_date=getattr(args, 'to_date', None)
    )
    return searcher.results


def _extract_logon_id(description):
    """Extract Logon ID (hex) from event description if present."""
    if not description:
        return None
    try:
        match = re.search(r"Logon ID:\s*(0x[0-9A-Fa-f]+)", description)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def output_timeline(events, fmt='jsonl', sessionize='none'):
    """Output a chronological timeline in JSONL or CSV with optional sessionization.

    Args:
        events (list): list of event dicts as produced by searcher
        fmt (str): 'jsonl' or 'csv'
        sessionize (str): 'none', 'user', 'host', 'logon', or 'log'
    """
    if not events:
        print("No matching events found.")
        return

    # Sort chronologically
    def parse_ts(e):
        try:
            return datetime.strptime(e.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
        except Exception:
            return datetime.min

    sorted_events = sorted(events, key=parse_ts)

    # Derive session key if requested
    for e in sorted_events:
        session = None
        if sessionize == 'user':
            session = e.get('user')
        elif sessionize == 'host':
            session = e.get('computer')
        elif sessionize == 'logon':
            session = _extract_logon_id(e.get('description'))
        elif sessionize == 'log':
            session = e.get('log_name')
        e['session'] = session

    if fmt == 'jsonl':
        for e in sorted_events:
            print(json.dumps(e, default=str))
    else:  # csv
        headers = ['timestamp', 'session', 'user', 'computer', 'log_name',
                   'event_id', 'level', 'source', 'process', 'category', 'description']
        print(','.join(headers))
        for e in sorted_events:
            row = []
            for h in headers:
                v = str(e.get(h, '')).replace(',', ';').replace(
                    '\n', ' ').replace('\r', ' ')
                row.append(f'"{v}"')
            print(','.join(row))


def load_compromise_config():
    """Load compromise.json configuration file."""
    try:
        config_path = os.path.join('config', 'compromise.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: compromise.json not found at {config_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in compromise.json: {e}")
        return None


def load_additional_config_events():
    """Load event IDs from other relevant config files."""
    additional_events = []
    relevant_configs = [
        'privilege_escalation.json',
        'persistence_autoruns.json', 
        'powershell_deep.json',
        'rdp_remote_access.json',
        'simple_privilege.json',
        'sysmon_core.json',
        'kerberos_anomalies.json',
        'network_wfp_anomalies.json'
    ]
    
    for config_file in relevant_configs:
        try:
            config_path = os.path.join('config', config_file)
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Extract event IDs from the config
                for key, value in config.items():
                    if isinstance(value, list):
                        # Filter for integer event IDs
                        event_ids = [e for e in value if isinstance(e, int)]
                        additional_events.extend(event_ids)
                    elif isinstance(value, dict):
                        # Handle nested structures
                        for sub_key, sub_value in value.items():
                            if isinstance(sub_value, list):
                                event_ids = [e for e in sub_value if isinstance(e, int)]
                                additional_events.extend(event_ids)
                
                print(f"  - Loaded {config_file}")
        except Exception as e:
            print(f"  - Warning: Could not load {config_file}: {e}")
    
    return additional_events


def hunt_compromise_indicators(hours_back=24, specific_date=None, from_date=None, to_date=None):
    """Hunt for compromise indicators using compromise.json configuration."""
    config = load_compromise_config()
    if not config:
        return None, 0
    
    print("=" * 80)
    print("COMPROMISE INDICATOR HUNTING")
    print("=" * 80)
    
    # Show what we're loading from compromise.json
    print(f"\nLoading from compromise.json:")
    for key in config.keys():
        if isinstance(config[key], list):
            if all(isinstance(x, int) for x in config[key]):
                print(f"  - {key}: {len(config[key])} event IDs")
            else:
                print(f"  - {key}: {len(config[key])} entries")
        elif isinstance(config[key], dict):
            print(f"  - {key}: {len(config[key])} mappings")
    
    # Initialize searcher
    exclude_dates = getattr(args, 'exclude_dates', None) if 'args' in globals() else None
    searcher = WindowsEventLogSearcher(exclude_dates=exclude_dates)
    
    # Get all event IDs from compromise.json
    all_compromise_events = []
    try:
        for category, events in config.items():
            if isinstance(events, list):
                # Filter out non-integer values
                valid_events = [e for e in events if isinstance(e, int)]
                all_compromise_events.extend(valid_events)
            elif category == 'correlate_event_chains' and isinstance(events, list):
                # Extract event IDs from correlation chains
                for chain in events:
                    if isinstance(chain, dict) and 'steps' in chain:
                        for step in chain.get('steps', []):
                            if isinstance(step, dict) and 'event_id' in step:
                                all_compromise_events.append(step['event_id'])
            elif category == 'hunt_queries' and isinstance(events, list):
                # Extract event IDs from hunt queries
                for query in events:
                    if isinstance(query, dict) and 'event_ids' in query:
                        all_compromise_events.extend(query['event_ids'])
    except Exception as e:
        print(f"Error processing config: {e}")
        return None, 0
    
    # Ask user if they want to include other relevant config files
    print(f"\nCurrent search includes {len(all_compromise_events)} event IDs from compromise.json")
    print("Would you like to include additional event IDs from other relevant config files?")
    print("Available configs: privilege_escalation.json, persistence_autoruns.json, powershell_deep.json, etc.")
    
    while True:
        user_input = input("Include other config files? [Y/N] (default: N): ").strip().upper()
        if user_input in ['Y', 'YES']:
            include_other_configs = True
            break
        elif user_input in ['N', 'NO', '']:  # Empty string for default
            include_other_configs = False
            break
        else:
            print("Please enter Y/YES or N/NO (or press Enter for default N)")
    
    # If user chose to include other configs, load them
    if include_other_configs:
        additional_events = load_additional_config_events()
        if additional_events:
            all_compromise_events.extend(additional_events)
            print(f"Added {len(additional_events)} additional event IDs from other config files")
    
    # Remove duplicates and sort
    unique_events = sorted(list(set(all_compromise_events)))
    
    print(f"Searching for {len(unique_events)} compromise-related event IDs...")
    
    # Search for events using the existing method
    try:
        # Store results in searcher object
        searcher.search_event_ids(
            event_ids=unique_events,
            hours_back=hours_back,
            output_format='json',
            quiet=True,
            specific_date=specific_date,
            from_date=from_date,
            to_date=to_date
        )
        # Get results from searcher object
        results = getattr(searcher, 'results', [])
    except Exception as e:
        print(f"Error searching for events: {e}")
        results = []
    
    return results, config


def analyze_event_chains(results, config):
    """Analyze event chains to detect attack patterns with TEMPORAL COHERENCE.
    Events must occur close together in time, not randomly scattered.
    Enhanced to consider LOLBins execution in chains."""
    if 'correlate_event_chains' not in config:
        return []
    
    from datetime import datetime, timedelta
    
    detected_chains = []
    chains = config['correlate_event_chains']
    
    # TEMPORAL COHERENCE SETTINGS
    MAX_CHAIN_DURATION_MINUTES = 60  # Chain events must occur within 60 minutes
    MAX_STEP_GAP_MINUTES = 30  # Max gap between consecutive steps
    
    # Group events by session/user for correlation
    events_by_session = {}
    for event in results:
        session_id = event.get('session', 'unknown')
        if session_id not in events_by_session:
            events_by_session[session_id] = []
        events_by_session[session_id].append(event)
    
    # Check each correlation chain
    for chain in chains:
        chain_name = chain.get('name', 'Unknown Chain')
        steps = chain.get('steps', [])
        
        for session_id, session_events in events_by_session.items():
            # Check if this session has events matching the chain
            matched_steps = []
            lolbin_detected = False
            privileged_execution = False
            
            for step in steps:
                step_event_id = step.get('event_id')
                step_source = step.get('source', 'Security')
                min_count = step.get('min_count', 1)  # Support burst detection (e.g., Kerberoasting)
                
                # Find ALL matching events in this session for this step
                step_matches = []
                for event in session_events:
                    if (event.get('event_id') == step_event_id and 
                        event.get('log_name', '').lower() == step_source.lower()):
                        step_matches.append(event)
                        
                        # Check if this step involves LOLBin execution
                        if event.get('risk_reasons'):
                            for reason in event.get('risk_reasons', []):
                                if 'lolb' in reason.lower():
                                    lolbin_detected = True
                                if 'privilege' in reason.lower():
                                    privileged_execution = True
                
                # Check if we have enough events for this step (min_count)
                if len(step_matches) >= min_count:
                    # Use the first match for timing (or closest to previous step)
                    matched_steps.append({
                        'step': step,
                        'event': step_matches[0],
                        'timestamp': step_matches[0].get('timestamp'),
                        'count': len(step_matches)
                    })
            
            # If we found multiple steps, check TEMPORAL COHERENCE
            if len(matched_steps) >= 2:
                # Parse timestamps and sort chronologically
                timestamped_steps = []
                for matched_step in matched_steps:
                    ts_str = matched_step['timestamp']
                    if ts_str:
                        try:
                            ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                            timestamped_steps.append({**matched_step, 'datetime': ts})
                        except:
                            pass  # Skip events with invalid timestamps
                
                if len(timestamped_steps) < 2:
                    continue  # Need at least 2 events with valid timestamps
                
                # Sort by time
                timestamped_steps.sort(key=lambda x: x['datetime'])
                
                # CHECK TEMPORAL COHERENCE
                first_event_time = timestamped_steps[0]['datetime']
                last_event_time = timestamped_steps[-1]['datetime']
                total_duration = (last_event_time - first_event_time).total_seconds() / 60.0  # minutes
                
                # Check if chain duration is reasonable (not scattered throughout the day)
                if total_duration > MAX_CHAIN_DURATION_MINUTES:
                    # Events too spread out - likely legitimate scattered activity
                    continue
                
                # Check gaps between consecutive steps
                max_gap = 0
                for i in range(1, len(timestamped_steps)):
                    gap = (timestamped_steps[i]['datetime'] - timestamped_steps[i-1]['datetime']).total_seconds() / 60.0
                    max_gap = max(max_gap, gap)
                
                if max_gap > MAX_STEP_GAP_MINUTES:
                    # Too long gap between steps - not a coherent chain
                    continue
                
                # PASSED TEMPORAL COHERENCE CHECKS - this is a legitimate chain
                base_confidence = len(timestamped_steps) / len(steps)
                
                # BONUS: Increase confidence for tight temporal clustering
                if total_duration < 10:  # Events within 10 minutes = very suspicious
                    base_confidence = min(base_confidence + 0.15, 1.0)  # +15% for tight clustering
                elif total_duration < 30:  # Events within 30 minutes = suspicious
                    base_confidence = min(base_confidence + 0.08, 1.0)  # +8% for moderate clustering
                
                # Increase confidence if LOLBin was detected in the chain
                if lolbin_detected:
                    base_confidence = min(base_confidence + 0.12, 1.0)  # +12% for LOLBin (reduced from 15%)
                
                # Further increase if LOLBin was executed with privileges
                if lolbin_detected and privileged_execution:
                    base_confidence = min(base_confidence + 0.08, 1.0)  # Additional +8% (reduced from 10%)
                
                detected_chains.append({
                    'chain_name': chain_name,
                    'session_id': session_id,
                    'matched_steps': timestamped_steps,
                    'confidence': base_confidence,
                    'lolbin_detected': lolbin_detected,
                    'privileged_execution': privileged_execution,
                    'duration_minutes': total_duration,
                    'max_gap_minutes': max_gap
                })
    
    return detected_chains


def calculate_compromise_likelihood(results, detected_chains, config):
    """Calculate the likelihood percentage that the host is compromised using advanced scoring methodology,
    with safeguards to reduce false positives (deduping, caps, temporal coherence, chain requirement)."""
    if not results:
        return 0.0

    # Load LOLBins for context-aware scoring
    lolbins = load_lolbins_list()
    
    # Event severity scoring (base scores)
    event_severity_scores = {
        # CRITICAL (20-25 points) - Immediate compromise indicators
        1102: 25,  # Log cleared (defense evasion)
        1100: 20,  # Event log service stopped
        1104: 20,  # Security log cleared
        4732: 24,  # Member added to local group (privilege escalation) - ENHANCED
        4728: 22,  # Member added to global group - ENHANCED
        4720: 20,  # User account created - MOVED TO CRITICAL
        
        # HIGH (12-18 points) - Strong compromise indicators
        4697: 18,  # Service installed (persistence)
        4648: 16,  # Logon with explicit credentials - ENHANCED
        4771: 15,  # Kerberos pre-authentication failed
        4672: 14,  # Special privileges assigned - ADDED
        4104: 14,  # PowerShell script block logging
        4698: 12,  # Scheduled task created (persistence)
        4722: 12,  # User account enabled
        4735: 12,  # Group changed
        
        # MEDIUM (6-10 points) - Moderate compromise indicators
        4625: 8,   # Failed logon (brute force)
        4768: 8,   # Kerberos TGT requested
        4769: 8,   # Kerberos service ticket requested
        7045: 7,   # Service creation
        8004: 6,   # PowerShell execution policy
        8005: 6,   # PowerShell execution policy
        
        # LOW (2-5 points) - Baseline events
        4688: 2,   # Process creation (baseline)
        1022: 1,   # DNS query (very common, low severity)
    }
    
    # Context-aware scoring multipliers
    def get_context_multiplier(event):
        """Calculate context-based multiplier for event scoring."""
        multiplier = 1.0
        process_name = (event.get('process') or '').lower()
        service_name = (event.get('service_name') or '').lower()
        service_path = (event.get('service_path') or '').lower()
        task_command = (event.get('task_command') or '').lower()
        description = (event.get('description') or '').lower()
        
        # LOLBin execution multiplier
        if any(lolbin in process_name or lolbin in service_path or lolbin in task_command 
               for lolbin in lolbins):
            multiplier *= 3.0  # 3x multiplier for LOLBin execution
        
        # Privileged execution multiplier
        if any(priv_indicator in description for priv_indicator in 
               ['administrator', 'system', 'privilege', 'elevated', 'runas']):
            multiplier *= 2.0  # 2x multiplier for privileged execution
        
        # Suspicious process names
        suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
                               'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe']
        if any(susp in process_name for susp in suspicious_processes):
            multiplier *= 1.5  # 1.5x multiplier for suspicious processes
        
        # Service persistence indicators
        if service_name and any(persist_indicator in service_name.lower() for persist_indicator in 
                               ['backdoor', 'shell', 'reverse', 'bind', 'listener']):
            multiplier *= 2.5  # 2.5x multiplier for suspicious service names
        
        # Scheduled task persistence
        if task_command and any(task_indicator in task_command.lower() for task_indicator in 
                               ['powershell', 'cmd', 'wscript', 'cscript', 'regsvr32']):
            multiplier *= 1.8  # 1.8x multiplier for suspicious task commands
        
        # Reduce impact of DNS queries (very common, not necessarily suspicious)
        if event.get('event_id') == 1022:
            multiplier *= 0.1  # 0.1x multiplier for DNS queries (significantly reduce their impact)
        
        return multiplier
    
    # Temporal scoring (recent events weighted higher)
    def get_temporal_multiplier(event):
        """Calculate temporal multiplier based on event recency."""
        try:
            from datetime import datetime, timedelta
            event_time = datetime.strptime(event.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
            hours_ago = (datetime.now() - event_time).total_seconds() / 3600
            
            if hours_ago <= 1:      # Last hour
                return 2.0
            elif hours_ago <= 6:     # Last 6 hours
                return 1.5
            elif hours_ago <= 24:    # Last 24 hours
                return 1.2
            elif hours_ago <= 72:    # Last 3 days
                return 1.0
            else:                   # Older
                return 0.8
        except:
            return 1.0  # Default if timestamp parsing fails
    
    # Build a filtered, de-duplicated list for scoring (same eid/computer/desc per-day)
    unique_keys = set()
    dedup_results = []
    for _ev in results:
        ts = (_ev.get('timestamp') or '')
        ev_date = ts.split(' ')[0] if ts else ''
        key = (
            ev_date,
            _ev.get('event_id'),
            (_ev.get('computer') or ''),
            hash(_ev.get('description') or '')
        )
        if key in unique_keys:
            continue
        unique_keys.add(key)
        dedup_results.append(_ev)

    # Strict high-confidence subset (exclude noisy IDs)
    strict_high_conf_ids = set([1102, 1100, 1104, 4697, 4698, 7045, 4720, 4728, 4732])
    configured_high_conf = set(config.get('prioritize_high_confidence_indicators', []))
    high_confidence_events = list(configured_high_conf.intersection(strict_high_conf_ids))

    # Calculate base scores with context and temporal multipliers
    total_score = 0
    high_confidence_count = 0
    dns_query_score = 0  # Track DNS query scores separately
    # Cap cumulative contribution by Event ID to avoid noisy overwhelming
    per_eid_score = {}
    per_eid_cap = 50.0

    for event in dedup_results:
        event_id = event.get('event_id')
        base_score = event_severity_scores.get(event_id, 1)  # Default 1 for unknown events
        
        # Apply context multiplier
        context_multiplier = get_context_multiplier(event)
        
        # Apply temporal multiplier
        temporal_multiplier = get_temporal_multiplier(event)
        
        # Calculate final score for this event
        event_score = base_score * context_multiplier * temporal_multiplier

        # Cap DNS query contributions to prevent overwhelming the score
        if event_id == 1022:
            dns_query_score += event_score
            # Cap total DNS query score at 10 points
            if dns_query_score > 10:
                continue  # Skip this DNS query beyond cap
        else:
            # Apply per-EventID cumulative cap
            current = per_eid_score.get(event_id, 0.0)
            if current < per_eid_cap:
                remaining = per_eid_cap - current
                to_add = event_score if event_score <= remaining else remaining
                if to_add > 0:
                    total_score += to_add
                    per_eid_score[event_id] = current + to_add
        
        # Count high confidence events
        if event_id in high_confidence_events:
            high_confidence_count += 1
    
    # Add capped DNS query score
    total_score += min(dns_query_score, 10)
    
    # Event chain scoring (VERY CONSERVATIVE - reduce false positives)
    # Further reduced base multiplier from 15 to 8 to prevent score inflation
    chain_score = 0
    for chain in detected_chains:
        base_chain_score = chain['confidence'] * 8  # REDUCED from 15 to 8 (73% reduction from original 30)
        chain_name = chain.get('chain_name', '').lower()
        
        # High-priority chain multipliers (FURTHER REDUCED)
        if 'brute-force' in chain_name or 'password spray' in chain_name:
            base_chain_score *= 1.4  # REDUCED from 1.8
        elif 'kerberoast' in chain_name or 'service ticket' in chain_name:
            base_chain_score *= 1.35  # REDUCED from 1.7
        elif 'unauthorized account' in chain_name or 'privilege escalation' in chain_name:
            base_chain_score *= 1.3  # REDUCED from 1.6
        elif 'credential dumping' in chain_name or 'antiforensics' in chain_name or 'cleanup' in chain_name:
            base_chain_score *= 1.35  # REDUCED from 1.7
        elif 'lateral movement' in chain_name or 'explicit credentials' in chain_name:
            base_chain_score *= 1.25  # REDUCED from 1.5
        elif 'powershell' in chain_name and 'fileless' in chain_name:
            base_chain_score *= 1.2  # REDUCED from 1.4
        elif 'scheduled task' in chain_name and 'persistence' in chain_name:
            base_chain_score *= 1.15  # REDUCED from 1.3
        
        # Bonus for LOLBin in chain (FURTHER REDUCED)
        if chain.get('lolbin_detected'):
            base_chain_score *= 1.1  # REDUCED from 1.2
        
        # Bonus for privileged execution in chain (FURTHER REDUCED)
        if chain.get('privileged_execution'):
            base_chain_score *= 1.08  # REDUCED from 1.15
        
        chain_score += base_chain_score
    
    # Pattern-based detection bonuses (specific attack indicators)
    pattern_bonus = 0
    
    # Detect Kerberoasting (burst of 4769 events)
    event_4769_count = sum(1 for e in dedup_results if e.get('event_id') == 4769)
    if event_4769_count >= 10:
        pattern_bonus += 40  # Strong indicator of Kerberoasting
    elif event_4769_count >= 5:
        pattern_bonus += 20  # Moderate indicator
    
    # Detect brute-force (multiple 4625 events)
    event_4625_count = sum(1 for e in dedup_results if e.get('event_id') == 4625)
    if event_4625_count >= 10:
        pattern_bonus += 35  # Strong brute-force indicator
    elif event_4625_count >= 5:
        pattern_bonus += 15  # Moderate brute-force
    
    # Detect 4625 → 4624 sequence (brute-force success)
    has_4625 = any(e.get('event_id') == 4625 for e in dedup_results)
    has_4624 = any(e.get('event_id') == 4624 for e in dedup_results)
    has_4672 = any(e.get('event_id') == 4672 for e in dedup_results)
    if has_4625 and has_4624 and has_4672:
        pattern_bonus += 30  # Brute-force followed by privileged access
    elif has_4625 and has_4624:
        pattern_bonus += 15  # Brute-force followed by success
    
    # Detect 4648 with remote indicators
    event_4648_count = sum(1 for e in dedup_results if e.get('event_id') == 4648)
    if event_4648_count >= 3:
        pattern_bonus += 25  # Multiple explicit credential usage
    
    # Hunt query match bonuses (conservative)
    hunt_query_bonus = 0
    for event in dedup_results:
        if event.get('risk_reasons'):
            for reason in event.get('risk_reasons', []):
                if 'hunt' in reason.lower() or 'query' in reason.lower():
                    hunt_query_bonus += 2  # reduce per-match weight to limit noise
    
    # High confidence indicator bonus (strict set only)
    high_confidence_bonus = high_confidence_count * 6

    # Temporal coherence factor: favor clusters within shorter windows
    from datetime import datetime
    times = []
    for ev in dedup_results:
        ts = ev.get('timestamp')
        if ts:
            try:
                times.append(datetime.strptime(ts, '%Y-%m-%d %H:%M:%S'))
            except Exception:
                pass
    temporal_factor = 1.0
    if times:
        earliest = min(times)
        latest = max(times)
        span_hours = max(0.0, (latest - earliest).total_seconds() / 3600.0)
        if span_hours <= 6:
            temporal_factor = 1.3
        elif span_hours <= 24:
            temporal_factor = 1.1
        else:
            temporal_factor = 0.85
    
    # Calculate final likelihood with WEIGHTED components
    # VERY CONSERVATIVE weighting to minimize false positives
    # Weighting: Chains (2.0x) > Pattern Bonus (1.3x) > Individual Events (1x) > Hunt Queries (0.2x)
    weighted_chain_score = chain_score * 2.0  # 2.0x multiplier for correlated chains (REDUCED from 2.5)
    weighted_pattern_bonus = pattern_bonus * 1.3  # 1.3x multiplier for pattern detection (REDUCED from 1.5)
    weighted_hunt_bonus = hunt_query_bonus * 0.2  # 0.2x multiplier for hunt queries (REDUCED from 0.3)
    
    final_score = (
        total_score +                    # Individual event scores (base weight)
        weighted_chain_score +           # Event chains (2.0x weight) - STRONGEST INDICATOR
        weighted_pattern_bonus +         # Pattern bonuses (1.3x weight)
        weighted_hunt_bonus +            # Hunt query bonuses (0.2x weight)
        high_confidence_bonus            # High confidence bonus (base weight)
    ) * temporal_factor
    
    # More sophisticated normalization
    # Scale based on event count and severity distribution
    event_count = len(dedup_results)
    if event_count == 0:
        return 0.0
    
    # Base normalization: score per event
    base_likelihood = (final_score / max(event_count, 1)) * 10  # Scale factor
    
    # Apply logarithmic scaling to prevent always hitting 100%
    import math
    if base_likelihood > 0:
        likelihood = min(100.0, 100 * (1 - math.exp(-base_likelihood / 50)))
    else:
        likelihood = 0.0
    
    # CHAIN-CENTRIC ADJUSTMENTS (VERY CONSERVATIVE):
    # Much stricter thresholds to minimize false positives
    if detected_chains:
        chain_count = len(detected_chains)
        # VERY conservative thresholds - require more chains for high likelihood
        if chain_count >= 5:
            likelihood = max(likelihood, 65.0)  # 5+ chains = high likelihood (was 4+, was 70%)
        elif chain_count >= 4:
            likelihood = max(likelihood, 55.0)  # 4 chains = moderate-high (was 70%)
        elif chain_count >= 3:
            likelihood = max(likelihood, 45.0)  # 3 chains = moderate (was 60%)
        elif chain_count >= 2:
            likelihood = max(likelihood, 35.0)  # 2 chains = low-moderate (was 50%)
        else:
            likelihood = max(likelihood, 25.0)  # 1 chain = low (was 35%)
    else:
        # If NO chains detected, cap likelihood to avoid false positives
        # Individual events without chains are weaker indicators
        likelihood = min(likelihood, 25.0)  # REDUCED from 35% to 25%
    
    # Ensure minimum threshold for high confidence events (minimal)
    if high_confidence_count > 0 and not detected_chains:
        likelihood = max(likelihood, 8.0)  # REDUCED from 10% when no chains
    
    # Cap at 100%
    likelihood = min(100.0, likelihood)
    
    return likelihood


def print_scoring_breakdown(results, detected_chains, config, likelihood):
    """Print detailed scoring breakdown for debugging and transparency."""
    if not results:
        return
    
    print(f"\nSCORING BREAKDOWN:")
    print("=" * 50)
    
    # Load LOLBins for context
    lolbins = load_lolbins_list()
    
    # Event severity scores (same as in calculate_compromise_likelihood)
    event_severity_scores = {
        1102: 25, 1100: 20, 1104: 20, 4732: 22, 4728: 20,
        4697: 18, 4720: 15, 4648: 15, 4771: 15, 4104: 14,
        4698: 12, 4722: 12, 4735: 12, 4625: 8, 4768: 8,
        4769: 8, 7045: 7, 8004: 6, 8005: 6, 4688: 2
    }
    
    # Count events by severity
    critical_count = sum(1 for e in results if event_severity_scores.get(e.get('event_id', 0), 0) >= 20)
    high_count = sum(1 for e in results if 12 <= event_severity_scores.get(e.get('event_id', 0), 0) < 20)
    medium_count = sum(1 for e in results if 6 <= event_severity_scores.get(e.get('event_id', 0), 0) < 12)
    low_count = sum(1 for e in results if event_severity_scores.get(e.get('event_id', 0), 0) < 6)
    
    print(f"Event Severity Distribution:")
    print(f"  Critical (20+ pts): {critical_count} events")
    print(f"  High (12-19 pts): {high_count} events") 
    print(f"  Medium (6-11 pts): {medium_count} events")
    print(f"  Low (2-5 pts): {low_count} events")
    
    # Context analysis
    lolbin_events = 0
    privileged_events = 0
    suspicious_process_events = 0
    
    for event in results:
        process_name = (event.get('process') or '').lower()
        service_path = (event.get('service_path') or '').lower()
        task_command = (event.get('task_command') or '').lower()
        description = (event.get('description') or '').lower()
        
        if any(lolbin in process_name or lolbin in service_path or lolbin in task_command for lolbin in lolbins):
            lolbin_events += 1
        
        if any(priv in description for priv in ['administrator', 'system', 'privilege', 'elevated', 'runas']):
            privileged_events += 1
        
        if any(susp in process_name for susp in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']):
            suspicious_process_events += 1
    
    print(f"\nContext Analysis:")
    print(f"  LOLBin executions: {lolbin_events}")
    print(f"  Privileged executions: {privileged_events}")
    print(f"  Suspicious processes: {suspicious_process_events}")
    
    # Pattern Detection
    event_4769_count = sum(1 for e in results if e.get('event_id') == 4769)
    event_4625_count = sum(1 for e in results if e.get('event_id') == 4625)
    event_4648_count = sum(1 for e in results if e.get('event_id') == 4648)
    has_4624 = any(e.get('event_id') == 4624 for e in results)
    has_4672 = any(e.get('event_id') == 4672 for e in results)
    
    print(f"\nPattern Detection:")
    if event_4769_count >= 10:
        print(f"  [!] Kerberoasting: {event_4769_count} service tickets (CRITICAL)")
    elif event_4769_count >= 5:
        print(f"  [!] Kerberoasting: {event_4769_count} service tickets (MODERATE)")
    
    if event_4625_count >= 10:
        print(f"  [!] Brute-Force: {event_4625_count} failed logons (CRITICAL)")
    elif event_4625_count >= 5:
        print(f"  [!] Brute-Force: {event_4625_count} failed logons (MODERATE)")
    
    if event_4625_count > 0 and has_4624 and has_4672:
        print(f"  [!] Brute-Force SUCCESS → Privileged Access (HIGH RISK)")
    elif event_4625_count > 0 and has_4624:
        print(f"  [!] Brute-Force SUCCESS detected")
    
    if event_4648_count >= 3:
        print(f"  [!] Explicit Credentials: {event_4648_count} uses (Lateral Movement?)")
    
    # Chain analysis with WEIGHTED SCORING and TEMPORAL INFO
    if detected_chains:
        print(f"\nAttack Chains: {len(detected_chains)} detected [2.0x WEIGHT MULTIPLIER]")
        print(f"  ** Chains weighted higher than individual events **")
        print(f"  ** Temporal coherence enforced: max 60min duration, 30min gaps **")
        for i, chain in enumerate(detected_chains, 1):
            duration = chain.get('duration_minutes', 0)
            print(f"  Chain {i}: {chain['chain_name']} (confidence: {chain['confidence']:.1%}, {duration:.1f}min duration)")
            if duration < 10:
                print(f"    - RAPID execution (<10min) [+15% confidence bonus]")
            elif duration < 30:
                print(f"    - Quick execution (<30min) [+8% confidence bonus]")
            if chain.get('lolbin_detected'):
                print(f"    - Contains LOLBin execution [+1.1x bonus]")
            if chain.get('privileged_execution'):
                print(f"    - Contains privileged execution [+1.08x bonus]")
    else:
        print(f"\nAttack Chains: 0 detected")
        print(f"  ** No chains detected - likelihood capped at 25% **")
    
    print(f"\n" + "=" * 50)
    print(f"SCORING WEIGHTS (Very Conservative):")
    print(f"  Event Chains: 2.0x (Strongest indicator)")
    print(f"  Pattern Bonuses: 1.3x")
    print(f"  Individual Events: 1.0x (base)")
    print(f"  Hunt Queries: 0.2x (noise reduction)")
    print(f"=" * 50)
    print(f"\nFinal Likelihood: {likelihood:.1f}%")
    if detected_chains:
        chain_count = len(detected_chains)
        if chain_count >= 5:
            print(f"  ** 5+ chains detected = minimum 65% likelihood **")
        elif chain_count >= 4:
            print(f"  ** 4 chains detected = minimum 55% likelihood **")
        elif chain_count >= 3:
            print(f"  ** 3 chains detected = minimum 45% likelihood **")
        elif chain_count >= 2:
            print(f"  ** 2 chains detected = minimum 35% likelihood **")
        else:
            print(f"  ** 1 chain detected = minimum 25% likelihood **")
    else:
        print(f"  ** No chains = maximum 25% likelihood (false positive reduction) **")
    print("=" * 50)


def load_lolbins_list():
    """Load LOLBins list from CSV file for context-aware scoring."""
    lolbins = []
    try:
        with open('ioc/lolbins_iocs.csv', 'r', encoding='utf-8') as f:
            import csv
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('value'):
                    # Extract just the executable name
                    lolbin_name = row['value'].split('\\')[-1].split('/')[-1].lower()
                    if lolbin_name not in lolbins:
                        lolbins.append(lolbin_name)
    except Exception as e:
        print(f"Warning: Could not load LOLBins list: {e}")
    
    return lolbins


def analyze_hunt_queries(results, config):
    """Analyze results against hunt queries from compromise.json."""
    if 'hunt_queries' not in config:
        return []
    
    matched_queries = []
    hunt_queries = config['hunt_queries']
    
    for query in hunt_queries:
        query_name = query.get('name', 'Unknown Query')
        query_event_ids = query.get('event_ids', [])
        
        # Find events matching this hunt query
        matching_events = []
        for e in results:
            if e.get('event_id') in query_event_ids:
                # For DNS queries (1022), only match if they're related to suspicious processes
                if e.get('event_id') == 1022:
                    process_name = (e.get('process') or '').lower()
                    description = (e.get('description') or '').lower()
                    # Only match DNS queries from suspicious processes or with suspicious domains
                    if any(susp in process_name for susp in ['powershell', 'cmd', 'wscript', 'cscript']) or \
                       any(susp in description for susp in ['suspicious', 'malware', 'c2', 'command']):
                        matching_events.append(e)
                else:
                    # For other events, match normally
                    matching_events.append(e)
        
        if matching_events:
            matched_queries.append({
                'name': query_name,
                'event_ids': query_event_ids,
                'matched_count': len(matching_events),
                'events': matching_events[:5]  # Keep first 5 for display
            })
    
    return matched_queries


def print_compromise_analysis(results, detected_chains, likelihood, config, export_events=False, output_file=None, raw_results=None):
    """Print detailed compromise analysis (scoped strictly to selected date/hour window).
    
    Args:
        results: Deduplicated results (for display/export)
        detected_chains: Detected attack chains
        likelihood: Compromise likelihood percentage
        config: Configuration dict
        export_events: Whether to export events to file
        output_file: Output file path
        raw_results: Raw (non-deduplicated) results for hunt query analysis (preserves burst patterns)
    """
    print(f"\nCOMPROMISE ANALYSIS RESULTS")
    print("=" * 80)

    # Use raw_results for hunt query analysis if provided, otherwise fall back to deduplicated results
    if raw_results is None:
        raw_results = results

    # Determine selected dates (specific date or date range) to scope all summaries
    target_dates = None
    if 'args' in globals():
        try:
            specific_date = getattr(args, 'specific_date', None)
            from_date = getattr(args, 'from_date', None)
            to_date = getattr(args, 'to_date', None)
            if specific_date:
                target_dates = {specific_date}
            elif from_date and to_date:
                from datetime import datetime, timedelta
                start_date = datetime.strptime(from_date, '%Y-%m-%d').date()
                end_date = datetime.strptime(to_date, '%Y-%m-%d').date()
                if start_date <= end_date:
                    target_dates = set()
                    d = start_date
                    while d <= end_date:
                        target_dates.add(d.strftime('%Y-%m-%d'))
                        d += timedelta(days=1)
        except Exception:
            target_dates = None

    # Filter results to target_dates if provided AND deduplicate (same logic as file export)
    def _within_scope(ev):
        if not target_dates:
            return True
        ts = ev.get('timestamp', '') or ''
        ev_date = ts.split(' ')[0] if ts else ''
        return ev_date in target_dates

    # Create RAW scoped results for hunt query analysis (no deduplication, preserves burst patterns)
    raw_scoped_results = [ev for ev in raw_results if _within_scope(ev)]
    
    # Deduplicate scoped_results for display/export
    unique_keys = set()
    scoped_results = []
    for ev in results:
        if not _within_scope(ev):
            continue
        # Same deduplication key as file export
        ts = ev.get('timestamp', '') or ''
        ev_date = ts.split(' ')[0] if ts else ''
        key = (
            ev_date,
            ev.get('event_id'),
            (ev.get('log_name') or ''),
            (ev.get('computer') or ''),
            hash(ev.get('description') or '')
        )
        if key in unique_keys:
            continue
        unique_keys.add(key)
        scoped_results.append(ev)

    # Filter detected chains to scope (all matched steps must be within range)
    scoped_chains = []
    for chain in detected_chains or []:
        steps = chain.get('matched_steps', [])
        if not target_dates:
            scoped_chains.append(chain)
        else:
            ok = True
            for s in steps:
                ts = (s.get('timestamp') or '')
                d = ts.split(' ')[0] if ts else ''
                if d not in target_dates:
                    ok = False
                    break
            if ok:
                scoped_chains.append(chain)

    # Analyze hunt query matches using RAW scoped results (preserves burst patterns for queries like brute-force detection)
    matched_queries = analyze_hunt_queries(raw_scoped_results, config)
    
    # Collect high-confidence indicators
    high_confidence_events = []
    if 'prioritize_high_confidence_indicators' in config:
        high_conf_ids = config['prioritize_high_confidence_indicators']
        high_confidence_events = [e for e in scoped_results if e.get('event_id') in high_conf_ids]
    
    # Collect high-risk events
    high_risk_events = [e for e in scoped_results if e.get('event_id') in [1102, 1100, 1104, 4720, 4728, 4732, 4697]]
    
    # ===== CONSOLE OUTPUT: SUMMARIES ONLY =====
    
    # Print summary of detected chains with TEMPORAL INFO
    if scoped_chains:
        print(f"\nDETECTED ATTACK CHAINS ({len(scoped_chains)} found):")
        for i, chain in enumerate(scoped_chains, 1):
            total_steps = len(chain['matched_steps'])
            duration = chain.get('duration_minutes', 0)
            max_gap = chain.get('max_gap_minutes', 0)
            indicators = []
            if chain.get('lolbin_detected'):
                indicators.append("LOLBin")
            if chain.get('privileged_execution'):
                indicators.append("Privileged")
            indicator_str = f" [{', '.join(indicators)}]" if indicators else ""
            
            # Show temporal clustering info
            if duration < 10:
                temporal_str = f", {duration:.1f}min duration ⚠ RAPID"
            elif duration < 30:
                temporal_str = f", {duration:.1f}min duration"
            else:
                temporal_str = f", {duration:.0f}min duration"
            
            print(f"  {i}. {chain['chain_name']} (Confidence: {chain['confidence']:.1%}, {total_steps} steps{temporal_str}){indicator_str}")
    
    # Print summary of hunt query matches
    if matched_queries:
        print(f"\nHUNT QUERY MATCHES ({len(matched_queries)} queries matched):")
        for query in matched_queries:
            print(f"  - {query['name']}: {query['matched_count']} event(s)")
    
    # Print summary of high-confidence events
    if high_confidence_events:
        print(f"\nHIGH-CONFIDENCE INDICATORS ({len(high_confidence_events)} found):")
        # Group by event ID and show counts
        event_id_counts = {}
        for event in high_confidence_events:
            eid = event.get('event_id')
            event_id_counts[eid] = event_id_counts.get(eid, 0) + 1
        for eid, count in sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  - Event ID {eid}: {count} occurrence(s)")
        if len(event_id_counts) > 10:
            print(f"  ... and {len(event_id_counts) - 10} more event types")
    
    # Print summary of high-risk events
    if high_risk_events:
        print(f"\nCRITICAL HIGH-RISK EVENTS ({len(high_risk_events)} found):")
        # Group by event ID and show counts
        event_id_counts = {}
        for event in high_risk_events:
            eid = event.get('event_id')
            event_id_counts[eid] = event_id_counts.get(eid, 0) + 1
        for eid, count in sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - Event ID {eid}: {count} occurrence(s)")
    
    # Show category breakdown
    if scoped_results:
        print(f"\nEVENT CATEGORY BREAKDOWN:")
        categories = {}
        for category, event_ids in config.items():
            if isinstance(event_ids, list) and all(isinstance(x, int) for x in event_ids):
                matched = [e for e in scoped_results if e.get('event_id') in event_ids]
                if matched:
                    categories[category] = len(matched)
        
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"   - {category}: {count} event(s)")
    
    # ===== STATS MATRIX (TEXT) =====
    try:
        def _print_stats_matrix():
            # Build per-category counts from scoped results only
            category_rows = []
            for category, event_ids in (config or {}).items():
                if isinstance(event_ids, list) and all(isinstance(x, int) for x in event_ids):
                    matched = [e for e in scoped_results if e.get('event_id') in event_ids]
                    if not matched:
                        continue
                    # counts
                    total = len(matched)
                    high_conf_ids = set(config.get('prioritize_high_confidence_indicators', []))
                    high_conf = sum(1 for e in matched if e.get('event_id') in high_conf_ids)
                    high_risk_ids = set([1102, 1100, 1104, 4720, 4728, 4732, 4697])
                    high_risk = sum(1 for e in matched if e.get('event_id') in high_risk_ids)
                    # hunt-matched
                    hunt_set = set()
                    for q in matched_queries:
                        for ev in q.get('events', []):
                            hunt_set.add(id(ev))
                    hunt = sum(1 for e in matched if id(e) in hunt_set)
                    # chain steps
                    chain_set = set()
                    for ch in scoped_chains:
                        for s in ch.get('matched_steps', []):
                            if 'event' in s:
                                chain_set.add(id(s['event']))
                    chain = sum(1 for e in matched if id(e) in chain_set)
                    category_rows.append((category, total, high_conf, high_risk, hunt, chain))

            if not category_rows:
                return

            # Sort by total desc
            category_rows.sort(key=lambda r: r[1], reverse=True)

            # Print matrix
            print("\nSTATISTICS MATRIX (scoped)")
            print("-" * 80)
            header = f"{'Category':40s} {'Total':>6s} {'HighConf':>8s} {'HighRisk':>8s} {'Hunt':>6s} {'Chain':>6s}"
            print(header)
            print("-" * 80)
            for row in category_rows[:20]:  # cap rows to keep compact
                name, total, hc, hr, hq, ch = row
                print(f"{name[:40]:40s} {total:6d} {hc:8d} {hr:8d} {hq:6d} {ch:6d}")
            print("-" * 80)

        _print_stats_matrix()
    except Exception:
        pass

    # ===== FILE EXPORT: DETAILED EVENT LISTS WITH MARKERS =====
    if export_events and output_file:
        try:
            # Create sets for quick lookups
            high_conf_ids = set()
            if 'prioritize_high_confidence_indicators' in config:
                high_conf_ids = set(config['prioritize_high_confidence_indicators'])
            
            high_risk_ids = set([1102, 1100, 1104, 4720, 4728, 4732, 4697])
            
            # Create sets of event IDs involved in chains and queries
            chain_event_ids = set()
            for chain in scoped_chains:
                for step in chain['matched_steps']:
                    if 'event' in step:
                        # Store the actual event object for matching
                        chain_event_ids.add(id(step['event']))
            
            query_event_ids = set()
            for query in matched_queries:
                for event in query['events']:
                    query_event_ids.add(id(event))

            # Strict date-filter and de-duplicate results for export safety
            target_dates = None
            if 'args' in globals():
                try:
                    specific_date = getattr(args, 'specific_date', None)
                    from_date = getattr(args, 'from_date', None)
                    to_date = getattr(args, 'to_date', None)
                    if specific_date:
                        target_dates = {specific_date}
                    elif from_date and to_date:
                        from datetime import datetime, timedelta
                        start_date = datetime.strptime(from_date, '%Y-%m-%d').date()
                        end_date = datetime.strptime(to_date, '%Y-%m-%d').date()
                        if start_date <= end_date:
                            target_dates = set()
                            d = start_date
                            while d <= end_date:
                                target_dates.add(d.strftime('%Y-%m-%d'))
                                d += timedelta(days=1)
                except Exception:
                    target_dates = None

            unique_keys = set()
            filtered_results = []
            for ev in results:
                ts = ev.get('timestamp', '') or ''
                ev_date = ts.split(' ')[0] if ts else ''
                if target_dates and ev_date not in target_dates:
                    continue
                # Build a stable uniqueness key
                key = (
                    ev_date,
                    ev.get('event_id'),
                    (ev.get('log_name') or ''),
                    (ev.get('computer') or ''),
                    hash(ev.get('description') or '')
                )
                if key in unique_keys:
                    continue
                unique_keys.add(key)
                filtered_results.append(ev)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                # Count high-confidence events (post-filter)
                high_conf_count = sum(1 for e in filtered_results if e.get('event_id') in high_conf_ids)
                
                # Export all discovered events with markers
                if filtered_results:
                    f.write(f"\n\nALL DISCOVERED EVENTS ({len(filtered_results)} total):\n")
                    f.write("=" * 80 + "\n")
                    f.write(f"Markers:\n")
                    f.write(f"  [HIGH-CONFIDENCE] = High-confidence compromise indicator\n")
                    f.write(f"  [HIGH-RISK] = Critical high-risk event\n")
                    f.write(f"  [ATTACK-CHAIN] = Part of detected attack chain\n")
                    f.write(f"  [HUNT-QUERY] = Matched hunt query\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for event in filtered_results:
                        timestamp = event.get('timestamp', 'Unknown')
                        event_id = event.get('event_id', 'Unknown')
                        log_name = event.get('log_name', 'Unknown')
                        source = event.get('source', 'Unknown')
                        user = event.get('user', 'Unknown')
                        computer = event.get('computer', 'Unknown')
                        process = event.get('process') or ''
                        description = event.get('description', 'N/A')
                        
                        # Extract service and task information
                        service_name = event.get('service_name') or ''
                        service_path = event.get('service_path') or ''
                        task_name = event.get('task_name') or ''
                        task_command = event.get('task_command') or ''
                        task_arguments = event.get('task_arguments') or ''
                        
                        # Build markers
                        markers = []
                        if event_id in high_conf_ids:
                            markers.append("HIGH-CONFIDENCE")
                        if event_id in high_risk_ids:
                            markers.append("HIGH-RISK")
                        if id(event) in chain_event_ids:
                            markers.append("ATTACK-CHAIN")
                        if id(event) in query_event_ids:
                            markers.append("HUNT-QUERY")
                        
                        marker_str = " [" + "] [".join(markers) + "]" if markers else ""
                        
                        f.write(f"[{timestamp}] {log_name} Event {event_id}{marker_str}\n")
                        f.write(f"  Computer: {computer}\n")
                        f.write(f"  User: {user}\n")
                        f.write(f"  Process: {process}\n")
                        f.write(f"  Source: {source}\n")
                        
                        # Add service information for service-related events
                        if service_name:
                            f.write(f"  Service Name: {service_name}\n")
                        if service_path:
                            f.write(f"  Service Path: {service_path}\n")
                        
                        # Add task information for scheduled task events
                        if task_name:
                            f.write(f"  Task Name: {task_name}\n")
                        if task_command:
                            full_command = task_command
                            if task_arguments:
                                full_command += f" {task_arguments}"
                            f.write(f"  Task Command: {full_command}\n")
                        
                        f.write(f"  Description: {description}\n")
                        f.write("-" * 80 + "\n")
            
            # Update export summary message (use filtered_results count, not all results)
            export_msg = f"{len(filtered_results)} event(s)"
            if high_conf_count > 0:
                export_msg += f" ({high_conf_count} high-confidence)"
            if len(scoped_chains) > 0:
                export_msg += f", {len(scoped_chains)} attack chain(s)"
            if len(matched_queries) > 0:
                export_msg += f", {len(matched_queries)} hunt query match(es)"
            if len(high_risk_events) > 0:
                export_msg += f", {len(high_risk_events)} high-risk"
            print(f"\n[INFO] Exported {export_msg} to: {output_file}")
        except Exception as e:
            print(f"\n[ERROR] Failed to export events to file: {e}")
    elif export_events and not output_file:
        print(f"\n[WARNING] --export-events requires -o output file to be specified")
    
    print("\n" + "=" * 80)
    print(f"COMPROMISE ANALYSIS RESULTS SUMMARY")
    print("=" * 80)
    print(f"Total Events Found: {len(results)}")
    print(f"Event Chains Detected: {len(detected_chains)}")
    print(f"Compromise Likelihood: {likelihood:.1f}%")
    
    if likelihood >= 80:
        print(f"\n[!] HIGH RISK: {likelihood:.1f}% - Strong indicators of compromise detected!")
    elif likelihood >= 50:
        print(f"\n[!] MEDIUM RISK: {likelihood:.1f}% - Some indicators of compromise detected")
    elif likelihood >= 20:
        print(f"\n[!] LOW RISK: {likelihood:.1f}% - Few indicators detected")
    else:
        print(f"\n[OK] LOW RISK: {likelihood:.1f}% - No significant indicators detected")
    
    print("\n" + "-" * 80)
    print("DISCLAIMER:")
    print("The compromise likelihood percentage is indicative only and should not be")
    print("taken as definitive proof of compromise. This is a probabilistic assessment")
    print("based on detected indicators and patterns. Always conduct thorough manual")
    print("investigation and analysis before drawing conclusions.")
    print("-" * 80)
    print("\n" + "=" * 80)


def show_logisek_banner():
    """Display the LOGISEK banner with ASCII art and information."""
    print("")

    # LOGISEK ASCII Art (using raw string to avoid escape sequence warnings)
    ascii_art = r"""
                                                                      
         _____   ______ _____ _______ _______ _     _
 |      |     | |  ____   |   |______ |______ |____/ 
 |_____ |_____| |_____| __|__ ______| |______ |    \_
                                                                  
                                                                      
"""

    # Print ASCII art in DarkMagenta
    try:
        from colorama import Fore, Style
        print(f"{Fore.MAGENTA}{ascii_art}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  ThreatHunting v1.0{Style.RESET_ALL}")
    except ImportError:
        # Fallback to regular print if colorama not available
        print(ascii_art)

    print("  GNU General Public License v3.0")
    print("  https://logisek.com")
    print("  info@logisek.com")
    print("")
    print("")


if __name__ == "__main__":
    import argparse
    import sys

    # Custom help formatter to show banner
    class BannerHelpFormatter(argparse.HelpFormatter):
        def format_help(self):
            # Capture the banner output
            import io
            import contextlib

            banner_output = io.StringIO()
            with contextlib.redirect_stdout(banner_output):
                show_logisek_banner()

            help_text = super().format_help()
            return banner_output.getvalue() + help_text

    parser = argparse.ArgumentParser(
        description='Windows Event Log Threat Hunting Tool',
        formatter_class=BannerHelpFormatter)
    parser.add_argument('--hours', type=int, default=24,
                        help='Hours to look back (default: 24)')
    parser.add_argument('--date', type=str, dest='specific_date',
                        help='Search for events from a specific date only (format: YYYY-MM-DD). Overrides --hours.')
    parser.add_argument('--from-date', type=str, dest='from_date',
                        help='Start date for date range search (format: YYYY-MM-DD). Use with --to-date. Overrides --hours and --date.')
    parser.add_argument('--to-date', type=str, dest='to_date',
                        help='End date for date range search (format: YYYY-MM-DD). Use with --from-date. Overrides --hours and --date.')
    parser.add_argument('--exclude-date', action='append', dest='exclude_dates',
                        help='Exclude events from specific date(s) (format: YYYY-MM-DD). Can be used multiple times.')
    parser.add_argument(
        '--format', choices=['json', 'jsonl', 'text', 'csv'], default='text', help='Output format')
    parser.add_argument('--categories', nargs='+',
                        help='Specific threat categories to search for')
    parser.add_argument('--list-categories', action='store_true',
                        help='List available threat categories')
    parser.add_argument('--check-availability', action='store_true',
                        help='Check how far back logs are available')
    parser.add_argument('--show-retention', action='store_true',
                        help='Show current log retention settings')
    parser.add_argument('--configure-retention', type=int, metavar='DAYS',
                        help='Configure log retention for specified days (requires admin)')
    parser.add_argument('--max-size', type=int, default=1024,
                        help='Maximum log size in MB (default: 1024)')
    parser.add_argument('--retention-policy', choices=['overwrite_as_needed', 'archive_when_full', 'never_overwrite'],
                        default='overwrite_as_needed', help='Log retention policy (default: overwrite_as_needed)')
    parser.add_argument('--force', action='store_true',
                        help='Force configuration even if admin privileges not detected')
    parser.add_argument('--method', choices=['registry', 'powershell', 'auto'], default='auto',
                        help='Configuration method: registry (reg.exe), powershell, or auto (default: auto)')
    parser.add_argument('--open-event-viewer',
                        action='store_true', help='Open Windows Event Viewer')
    parser.add_argument('--open-log-directory', action='store_true',
                        help='Open Windows Event Log directory')
    parser.add_argument('--open-both', action='store_true',
                        help='Open both Event Viewer and Log directory')
    parser.add_argument(
        '--config', type=str, help='Path to JSON configuration file with custom Event IDs')
    parser.add_argument('--configs', nargs='+', type=str,
                        help='Multiple configuration files to merge (base to last is override order)')
    parser.add_argument('--preset', type=str,
                        help='Named preset (e.g., accessible, advanced, privilege, event_ids) resolves to config/<name>.json')
    parser.add_argument('--event-ids', nargs='+', type=int,
                        help='Explicit Event ID list to search (overrides categories unless --all-events is used)')
    parser.add_argument('-o', '--output', type=str,
                        help='Write results to file (UTF-8). Incompatible with --matrix + non-text formats.')
    parser.add_argument(
        '--level', type=str, choices=['Error', 'Warning', 'Information', 'Critical', 'Verbose'],
        help='Filter events by level (Error, Warning, Information, Critical, Verbose)')
    parser.add_argument(
        '--level-all', type=str, choices=['Error', 'Warning', 'Information', 'Critical', 'Verbose'],
        help='Search for ALL events of specified level, ignoring Event ID filter')
    parser.add_argument(
        '--levels-all', nargs='+', type=str, choices=['Error', 'Warning', 'Information', 'Critical', 'Verbose'],
        help='Search for ALL events of the specified levels (multiple), ignoring Event ID filter')
    parser.add_argument(
        '--matrix', action='store_true',
        help='Display results in a user-friendly matrix format')
    parser.add_argument(
        '--log-filter', type=str, choices=['Application', 'Security', 'Setup', 'System'],
        help='Filter results to specific log type (Application, Security, Setup, System)')
    parser.add_argument(
        '--source-filter', type=str,
        help='Filter results where source contains the specified string')
    parser.add_argument(
        '--description-filter', type=str,
        help='Filter results where description contains the specified string')
    parser.add_argument('--no-admin-warning', action='store_true',
                        help='Suppress non-elevated admin warning')
    parser.add_argument('--elevate', action='store_true',
                        help='If not elevated, relaunch this script with Administrator privileges')
    parser.add_argument('--timeline', choices=['jsonl', 'csv'],
                        help='Output a chronological timeline (jsonl or csv) instead of standard formats')
    parser.add_argument('--sessionize', choices=['none', 'user', 'host', 'logon', 'log'], default='none',
                        help='Group timeline events by session key: user, host, logon (Logon ID), or log')
    parser.add_argument('--all-events', action='store_true',
                        help='Search ALL events (ignore Event IDs/categories and level filters)')
    parser.add_argument('--max-events', type=int, default=0,
                        help='Maximum number of events to check per log (0 = no limit). Replaces previous ~1000 cap')
    parser.add_argument('--concurrency', type=int, default=1,
                        help='Number of logs to process in parallel (1 = sequential)')
    parser.add_argument('--progress', action='store_true',
                        help='Show tqdm progress bars per log (requires tqdm)')
    parser.add_argument('--check-service', action='store_true',
                        help='Check Windows Event Log service status and exit')
    parser.add_argument('--evtx', nargs='+', type=str,
                        help='One or more .evtx files or directories to parse offline (searches recursively)')
    # LOLBAS updater
    parser.add_argument('--update-lolbas-iocs', action='store_true',
                        help='Fetch latest LOLBAS catalog and generate ioc/lolbas_iocs.csv')
    parser.add_argument('--lolbas-url', type=str, default='https://lolbas-project.github.io/api/lolbas.json',
                        help='LOLBAS API URL (default: https://lolbas-project.github.io/api/lolbas.json)')
    # Multi-host/remote collection
    parser.add_argument('--hosts', nargs='+', type=str,
                        help='One or more remote hosts to query (IP addresses or hostnames)')
    parser.add_argument('--hosts-file', type=str,
                        help='File containing list of remote hosts (one per line)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Timeout in seconds for remote host connections (default: 30)')
    parser.add_argument('--parallel-hosts', type=int, default=5,
                        help='Number of hosts to query in parallel (default: 5)')
    parser.add_argument('--username', type=str,
                        help='Username for remote authentication')
    parser.add_argument('--password', type=str,
                        help='Password for remote authentication (not recommended - use key-based auth)')
    parser.add_argument('--domain', type=str,
                        help='Domain for remote authentication')
    parser.add_argument('--auth-method', choices=['winrm', 'wmi', 'ssh'], default='winrm',
                        help='Authentication method for remote hosts (default: winrm)')
    # SSH remoting options
    parser.add_argument('--ssh-user', type=str,
                        help='SSH username for --auth ssh')
    parser.add_argument('--ssh-key', type=str,
                        help='Path to SSH private key for --auth ssh')
    parser.add_argument('--ssh-port', type=int, default=22,
                        help='SSH port (default: 22)')
    # WEF
    parser.add_argument('--wef-endpoint', type=str,
                        help='Windows Event Forwarding collector hostname/IP (queries ForwardedEvents)')
    # Remote strict mode
    parser.add_argument('--strict-remote', action='store_true',
                        help='Fail if remote collection fails or returns no results; do not fallback to local')
    # Output sinks
    parser.add_argument('--webhook', type=str,
                        help='HTTP endpoint to POST results (JSONL when --format jsonl, JSON otherwise)')
    parser.add_argument('--hec-url', type=str,
                        help='Splunk HEC URL (e.g., https://splunk:8088/services/collector)')
    parser.add_argument('--hec-token', type=str,
                        help='Splunk HEC token')
    parser.add_argument('--sink-batch', type=int, default=500,
                        help='Sink batch size (default 500)')
    # Sigma
    parser.add_argument('--sigma-dir', type=str,
                        help='Directory with Sigma YAML rules to load and evaluate locally')
    parser.add_argument('--sigma-boost', type=int, default=10,
                        help='Score boost per matched Sigma rule (default 10)')
    # IOCs
    parser.add_argument('--ioc', type=str,
                        help='Path to IOC file (CSV/TXT/STIX JSON) containing hashes, IPs, domains, or substrings')
    parser.add_argument('--ioc-format', type=str, choices=['csv', 'txt', 'stix'], default='csv',
                        help='IOC input format (default csv). CSV headers: type,value')
    parser.add_argument('--ioc-boost', type=int, default=5,
                        help='Score boost per IOC match (default 5)')
    parser.add_argument('--allowlist', type=str,
                        help='Path to JSON allowlist file to suppress known/expected activity (event_ids, sources, users, process_regex, description_regex)')
    parser.add_argument('--suppress', nargs='*',
                        help='Ad-hoc suppress rules like source:Security-SPP eid:4688 user:DOMAIN\\user process:regex desc:regex')
    # Regex-capable field filters
    parser.add_argument('--user-filter', type=str,
                        help='Regex to match user (e.g., DOMAIN\\user or user)')
    parser.add_argument('--process-filter', type=str,
                        help='Regex to match process/image path')
    parser.add_argument('--parent-filter', type=str,
                        help='Regex to match parent process/image')
    parser.add_argument('--ip-filter', type=str,
                        help='Regex to match source IP address')
    parser.add_argument('--port-filter', type=str,
                        help='Regex to match source port')
    parser.add_argument('--logon-type-filter', type=str,
                        help='Regex to match Logon Type value (e.g., 2,3,10)')
    parser.add_argument('--bool', choices=['and', 'or'], default='and',
                        help='Combine field filters with AND/OR (default AND)')
    parser.add_argument('--not', dest='negate', action='store_true',
                        help='Negate the combined field filter result (NOT)')
    parser.add_argument('--compromised', action='store_true',
                        help='Hunt for compromise indicators using compromise.json and calculate likelihood percentage')
    parser.add_argument('--export-events', action='store_true',
                        help='Export all discovered events to file (use with --compromised and -o output)')
    parser.add_argument('--scoring-breakdown', action='store_true',
                        help='Show detailed scoring breakdown for compromise likelihood calculation')
    parser.add_argument('--deduplicate', action='store_true',
                        help='Remove duplicate events from results (regular mode only; compromise mode always deduplicates). Events are considered duplicates if they have the same date, event ID, log name, computer, and description.')

    args = parser.parse_args()
    # expose args globally for helper access
    globals()['args'] = args

    # Show LOGISEK banner for all executions (except help)
    show_logisek_banner()

    # Validate incompatible flags
    if args.matrix and args.format in ['json', 'csv']:
        print("Error: --matrix is incompatible with --format json/csv. Use --format text or omit --matrix.")
        sys.exit(2)

    # Load Event IDs configuration (single/multiple/preset)
    EVENTS = None
    loaded_paths = []
    if args.preset:
        preset_map = {
            'accessible': os.path.join('config', 'accessible_events.json'),
            'advanced': os.path.join('config', 'advanced_events.json'),
            'common': os.path.join('config', 'common_events.json'),
            'privilege': os.path.join('config', 'privilege_escalation.json'),
            'simple_privilege': os.path.join('config', 'simple_privilege.json'),
            'event_ids': os.path.join('config', 'event_ids.json'),
            'custom': os.path.join('config', 'custom_events.json')
        }
        resolved = preset_map.get(args.preset.lower())
        if resolved and os.path.exists(resolved):
            cfg = load_event_ids_from_json(resolved)
            ok, err = validate_config_schema(cfg) if cfg else (
                False, 'Invalid/empty config')
            if ok:
                EVENTS = cfg
                loaded_paths.append(resolved)
            else:
                print(
                    f"Preset '{args.preset}' failed schema validation: {err}")
        else:
            print(f"Preset '{args.preset}' not recognized or file not found.")

    if args.config and not EVENTS:
        cfg = load_event_ids_from_json(args.config)
        ok, err = validate_config_schema(cfg) if cfg else (
            False, 'Invalid/empty config')
        if ok:
            EVENTS = cfg
            loaded_paths.append(args.config)
        else:
            print(f"Config '{args.config}' failed schema validation: {err}")

    if args.configs:
        merged = EVENTS or {}
        for path in args.configs:
            cfg = load_event_ids_from_json(path)
            ok, err = validate_config_schema(cfg) if cfg else (
                False, 'Invalid/empty config')
            if ok:
                merged, diff = merge_configs_with_diff(merged, cfg)
                print_config_diff(diff, quiet=False)
                loaded_paths.append(path)
            else:
                print(f"Config '{path}' failed schema validation: {err}")
        EVENTS = merged if merged else EVENTS

    if not EVENTS:
        EVENTS = get_default_events()

    # Calculate all unique Event IDs
    ALL_EVENT_IDS = sorted({eid for cat in EVENTS.values() for eid in cat})

    print(
        f"Loaded {len(ALL_EVENT_IDS)} unique Event IDs from {len(EVENTS)} categories")

    # Warn or elevate if not running with Administrator privileges (UAC-aware)
    try:
        is_admin = False
        try:
            # This checks the current process token elevation under UAC
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            # Fallback to previous heuristic if shell32 is unavailable
            try:
                is_admin = bool(win32security.IsUserAnAdmin())
            except Exception:
                is_admin = False

        if not is_admin:
            if getattr(args, 'elevate', False):
                # Re-launch the script elevated using ShellExecute 'runas'
                try:
                    script_path = os.path.abspath(__file__)
                    # Rebuild args excluding the --elevate flag to avoid recursion
                    child_args = [script_path] + \
                        [a for a in sys.argv[1:] if a != '--elevate']
                    params = ' '.join(
                        [f'"{a}"' if ' ' in a or a.startswith('-') else a for a in child_args])
                    rc = ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, params, None, 1)
                    if rc <= 32:
                        print(
                            "Failed to relaunch elevated. Please run this script from an elevated prompt.")
                        # If elevation failed, still show the warning unless suppressed
                        if not getattr(args, 'no-admin-warning', False):
                            print(
                                "WARNING: Administrator privileges not detected. This script works best when run elevated.")
                            print(
                                "Some logs (e.g., 'Security') and configuration actions may be inaccessible without elevation.")
                            print(
                                "Run from an elevated PowerShell or Command Prompt for full functionality.")
                    else:
                        # Successfully initiated elevation; exit current process
                        sys.exit(0)
                except Exception:
                    # On failure, show warning unless suppressed
                    if not getattr(args, 'no-admin-warning', False):
                        print(
                            "WARNING: Administrator privileges not detected. This script works best when run elevated.")
                        print(
                            "Some logs (e.g., 'Security') and configuration actions may be inaccessible without elevation.")
                        print(
                            "Run from an elevated PowerShell or Command Prompt for full functionality.")
            else:
                if not getattr(args, 'no-admin-warning', False):
                    print(
                        "WARNING: Administrator privileges not detected. This script works best when run elevated.")
                    print(
                        "Some logs (e.g., 'Security') and configuration actions may be inaccessible without elevation.")
                    print(
                        "Run from an elevated PowerShell or Command Prompt for full functionality.")
    except Exception:
        pass

    if args.list_categories:
        print("Available threat hunting categories:")
        for category, event_ids in EVENTS.items():
            print(f"  {category}: {len(event_ids)} Event IDs")
        sys.exit(0)

    if getattr(args, 'check_service', False):
        def check_eventlog_service_status():
            try:
                print("Checking Windows Event Log service (eventlog)...")
                # Query runtime state
                r = subprocess.run(['sc', 'query', 'eventlog'],
                                   capture_output=True, text=True)
                state = 'Unknown'
                if r.stdout:
                    for line in r.stdout.splitlines():
                        if 'STATE' in line:
                            state = line.split(':', 1)[1].strip()
                            break
                # Query configuration (start type)
                r2 = subprocess.run(['sc', 'qc', 'eventlog'],
                                    capture_output=True, text=True)
                start_type = 'Unknown'
                if r2.stdout:
                    for line in r2.stdout.splitlines():
                        if 'START_TYPE' in line:
                            start_type = line.split(':', 1)[1].strip()
                            break
                print(f"  Service: eventlog")
                print(f"  State:   {state}")
                print(f"  Start:   {start_type}")
                if 'RUNNING' not in state.upper():
                    print(
                        "\nThe Event Log service is not running. You may start it with:")
                    print("  sc start eventlog")
                sys.exit(0)
            except Exception as e:
                print(f"Error checking service status: {e}")
                sys.exit(1)
        check_eventlog_service_status()

    if getattr(args, 'update_lolbas_iocs', False):
        def update_lolbas_iocs(api_url, out_path=os.path.join('ioc', 'lolbins_iocs.csv')):
            try:
                if requests is None:
                    print("requests not installed; cannot fetch LOLBAS API.")
                    sys.exit(1)
                print(f"Fetching LOLBAS catalog: {api_url}")
                r = requests.get(api_url, timeout=20)
                r.raise_for_status()
                data = r.json()
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                # Write as substring IOCs: binary names and command patterns
                with open(out_path, 'w', encoding='utf-8', newline='') as f:
                    f.write('type,value\n')
                    for entry in data:
                        # Extract binary name
                        name = (entry.get('Name') or '').strip()
                        if name:
                            f.write(f'substring,{name.lower()}\n')

                        # Extract commands and their patterns
                        commands = entry.get('Commands', [])
                        for cmd in commands:
                            command_text = (cmd.get('Command') or '').strip()
                            if command_text:
                                # Extract executable names and suspicious patterns
                                parts = command_text.split()
                                for part in parts:
                                    if part.endswith('.exe') or part.endswith('.vbs') or part.endswith('.ps1') or part.endswith('.bat'):
                                        f.write(f'substring,{part.lower()}\n')
                                    # Look for suspicious patterns
                                    if any(pattern in part.lower() for pattern in ['-enc', 'downloadstring', 'iex', 'bypass', 'amsi']):
                                        f.write(f'substring,{part.lower()}\n')

                        # Extract full paths
                        full_paths = entry.get('Full_Path', [])
                        for path_entry in full_paths:
                            path = (path_entry.get('Path') or '').strip()
                            if path:
                                exe_name = os.path.basename(path)
                                if exe_name:
                                    f.write(f'substring,{exe_name.lower()}\n')

                print(f"Wrote LOLBAS IOCs: {out_path}")
                sys.exit(0)
            except Exception as e:
                print(f"Failed to update LOLBAS IOCs: {e}")
                sys.exit(1)
        update_lolbas_iocs(args.lolbas_url)

    if args.check_availability:
        searcher = WindowsEventLogSearcher()
        searcher.check_log_availability()
        sys.exit(0)

    if args.show_retention:
        searcher = WindowsEventLogSearcher()
        searcher.show_current_retention_settings()
        sys.exit(0)

    # Handle compromised hunting
    if args.compromised:
        try:
            # Hunt for compromise indicators
            # Only use hours_back if no specific date or date range is provided
            hours_back = args.hours
            if getattr(args, 'specific_date', None) or getattr(args, 'from_date', None):
                hours_back = 24  # Default fallback, will be overridden by date parameters
            
            results, config = hunt_compromise_indicators(
                hours_back=hours_back, 
                specific_date=getattr(args, 'specific_date', None),
                from_date=getattr(args, 'from_date', None),
                to_date=getattr(args, 'to_date', None)
            )
            
            if results is None:
                print("Failed to load compromise configuration")
                sys.exit(1)
            
            # Store raw results for hunt query analysis (which may need to see burst patterns)
            raw_results = results
            
            # ANALYZE EVENT CHAINS FIRST (before deduplication)
            # This is critical because some chains require multiple events of the same type
            # (e.g., brute-force detection needs 5+ failed logons, Kerberoasting needs 10+ ticket requests)
            detected_chains = analyze_event_chains(raw_results, config)
            
            # DEDUPLICATE results AFTER chain analysis to avoid breaking chain detection
            # but BEFORE likelihood scoring to avoid score inflation
            unique_keys = set()
            deduplicated_results = []
            for ev in raw_results:
                ts = ev.get('timestamp', '') or ''
                ev_date = ts.split(' ')[0] if ts else ''
                key = (
                    ev_date,
                    ev.get('event_id'),
                    (ev.get('log_name') or ''),
                    (ev.get('computer') or ''),
                    hash(ev.get('description') or '')
                )
                if key in unique_keys:
                    continue
                unique_keys.add(key)
                deduplicated_results.append(ev)
            
            # Calculate compromise likelihood (uses deduplicated results)
            likelihood = calculate_compromise_likelihood(deduplicated_results, detected_chains, config)
            
            # Determine output file for event export
            output_file = getattr(args, 'output', None)
            export_events = getattr(args, 'export_events', False)
            
            # Print analysis: Pass BOTH raw (for hunt queries) and deduplicated (for display)
            print_compromise_analysis(deduplicated_results, detected_chains, likelihood, config, export_events, output_file, raw_results=raw_results)
            
            # Show scoring breakdown if requested
            if getattr(args, 'scoring_breakdown', False):
                print_scoring_breakdown(deduplicated_results, detected_chains, config, likelihood)
            
            # Exit with appropriate code based on likelihood
            if likelihood >= 50:
                sys.exit(1)  # High/medium risk
            else:
                sys.exit(0)  # Low risk
                
        except Exception as e:
            print(f"Error during compromise hunting: {e}")
            sys.exit(1)

    if args.open_both:
        searcher = WindowsEventLogSearcher()
        print("Opening both Event Viewer and Log directory...")
        viewer_success = searcher.open_event_viewer()
        directory_success = searcher.open_log_directory()
        sys.exit(0 if (viewer_success and directory_success) else 1)
    elif args.open_event_viewer:
        searcher = WindowsEventLogSearcher()
        success = searcher.open_event_viewer()
        sys.exit(0 if success else 1)
    elif args.open_log_directory:
        searcher = WindowsEventLogSearcher()
        success = searcher.open_log_directory()
        sys.exit(0 if success else 1)

    if args.configure_retention:
        searcher = WindowsEventLogSearcher()

        # Choose configuration method
        if args.method == 'powershell':
            success = searcher.configure_log_retention_powershell(
                days=args.configure_retention,
                max_size_mb=args.max_size,
                retention_policy=args.retention_policy
            )
        elif args.method == 'registry':
            success = searcher.configure_log_retention_registry(
                days=args.configure_retention,
                max_size_mb=args.max_size,
                retention_policy=args.retention_policy
            )
        else:  # auto method
            print("Auto-detecting best configuration method...")

            # Try PowerShell first (most reliable)
            print("Trying PowerShell method...")
            success = searcher.configure_log_retention_powershell(
                days=args.configure_retention,
                max_size_mb=args.max_size,
                retention_policy=args.retention_policy
            )

            # If PowerShell fails, try registry method
            if not success:
                print("\nPowerShell method failed. Trying registry method...")
                success = searcher.configure_log_retention_registry(
                    days=args.configure_retention,
                    max_size_mb=args.max_size,
                    retention_policy=args.retention_policy
                )

                # If both fail, try the original method as last resort
                if not success:
                    print("\nRegistry method failed. Trying direct registry access...")
                    success = searcher.configure_log_retention(
                        days=args.configure_retention,
                        max_size_mb=args.max_size,
                        retention_policy=args.retention_policy,
                        force=args.force
                    )

        sys.exit(0 if success else 1)

    try:
        # Handle remote hosts
        remote_hosts = []
        if args.hosts:
            remote_hosts.extend(args.hosts)
        if args.hosts_file:
            try:
                with open(args.hosts_file, 'r') as f:
                    file_hosts = [line.strip() for line in f if line.strip()]
                    remote_hosts.extend(file_hosts)
            except Exception as e:
                print(f"Error reading hosts file '{args.hosts_file}': {e}")
                sys.exit(1)

        # Determine which level filter to use
        if args.levels_all:
            level_filter = set(args.levels_all)
            level_all = True
        else:
            level_filter = args.level_all if args.level_all else args.level
            level_all = bool(args.level_all)

        def run_search(quiet=False):
            if remote_hosts:
                # Remote search
                searcher = WindowsEventLogSearcher(
                    remote_hosts=remote_hosts,
                    timeout=args.timeout,
                    parallel_hosts=args.parallel_hosts,
                    username=args.username,
                    password=args.password,
                    domain=args.domain,
                    auth_method=args.auth_method,
                    exclude_dates=getattr(args, 'exclude_dates', None)
                )
                # attach SSH extras if present
                if args.auth_method == 'ssh':
                    searcher.ssh_key = args.ssh_key
                    searcher.ssh_port = args.ssh_port

                # Get event IDs to search
                if args.event_ids:
                    event_ids = args.event_ids
                elif args.categories:
                    event_ids = []
                    for category in args.categories:
                        if category in EVENTS:
                            event_ids.extend(EVENTS[category])
                else:
                    event_ids = list(ALL_EVENT_IDS) if ALL_EVENT_IDS else []

                results = searcher.search_remote_hosts(
                    event_ids=event_ids,
                    hours_back=args.hours,
                    output_format=args.format,
                    level_filter=level_filter,
                    level_all=level_all,
                    matrix_format=args.matrix,
                    log_filter=args.log_filter,
                    source_filter=args.source_filter,
                    description_filter=args.description_filter,
                    quiet=quiet,
                    field_filters={
                        'user': args.user_filter,
                        'process': args.process_filter,
                        'parent': args.parent_filter,
                        'ip': args.ip_filter,
                        'port': args.port_filter,
                        'logon_type': args.logon_type_filter
                    },
                    bool_logic=args.bool,
                    negate=args.negate,
                    max_events=args.max_events,
                    progress=args.progress,
                    allowlist=args.allowlist,
                    suppress_rules=args.suppress
                )

                # Enforce strict remote behavior
                if args.strict_remote and not results:
                    print(
                        "Remote collection returned no results or failed. --strict-remote is set; exiting with error.")
                    sys.exit(2)
                # Prepare output flags and output results
                searcher.matrix_format = args.matrix
                searcher.quiet = quiet
                searcher._output_results(args.format)
            else:
                # Local search
                search_threat_indicators(
                    hours_back=args.hours,
                    output_format=args.format,
                    specific_categories=args.categories,
                    level_filter=level_filter,
                    level_all=level_all,
                    matrix_format=args.matrix,
                    log_filter=args.log_filter,
                    source_filter=args.source_filter,
                    description_filter=args.description_filter,
                    quiet=quiet,
                    specific_date=getattr(args, 'specific_date', None),
                    from_date=getattr(args, 'from_date', None),
                    to_date=getattr(args, 'to_date', None)
                )

        if args.output and not args.compromised:
            # Inform about matrix/text expectations
            if args.matrix and args.format != 'text':
                print("Note: For --matrix output, --format is treated as text.")
            try:
                with open(args.output, 'w', encoding='utf-8', errors='replace') as f:
                    with redirect_stdout(f):
                        run_search(quiet=True)
                print(f"Results written to: {args.output}")
            except Exception as e:
                print(f"Error writing to output file '{args.output}': {e}")
                sys.exit(1)
        else:
            # Unified run path (respects remote_hosts if provided)
            run_search(quiet=False)

            # Send results to sinks if requested
            if getattr(args, 'webhook', None) or (getattr(args, 'hec_url', None) and getattr(args, 'hec_token', None)):
                # results already in searcher.results via global flow; construct a lightweight sender
                sender = WindowsEventLogSearcher()
                sender.results = searcher.results if 'searcher' in locals() else []
                sender.send_sinks(webhook_url=getattr(args, 'webhook', None), hec_url=getattr(args, 'hec_url', None), hec_token=getattr(
                    args, 'hec_token', None), batch_size=getattr(args, 'sink_batch', 500), use_jsonl=(args.format == 'jsonl'))
    except KeyboardInterrupt:
        print("\nSearch interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
