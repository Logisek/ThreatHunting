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
    def __init__(self):
        self.logs = ['Application', 'Security', 'Setup', 'System']
        self.results = []

    def search_event_ids(self, event_ids, hours_back=24, output_format='json', level_filter=None, level_all=False, matrix_format=False, log_filter=None, source_filter=None, description_filter=None, quiet=False):
        """
        Search for specific Event IDs in Windows Event Logs

        Args:
            event_ids (list): List of Event IDs to search for
            hours_back (int): How many hours back to search (default: 24)
            output_format (str): Output format - 'json', 'text', or 'csv'
            level_filter (str): Filter events by level (Error, Warning, Information, etc.)
            level_all (bool): If True, search for all events of the specified level, ignoring Event ID filter
            matrix_format (bool): If True, display results in matrix format
            log_filter (str): Filter results to specific log type
            source_filter (str): Filter results where source contains this string
            description_filter (str): Filter results where description contains this string
        """
        start_time = datetime.now() - timedelta(hours=hours_back)

        if not quiet:
            if level_all:
                print(f"Searching for ALL {level_filter} events (ignoring Event ID filter)")
            else:
                print(f"Searching for Event IDs: {event_ids}")
                if level_filter:
                    print(f"Level filter: {level_filter}")
            print(
                f"Time range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Logs: {', '.join(self.logs)}")
            print("-" * 80)

        self.level_filter = level_filter
        self.level_all = level_all
        self.matrix_format = matrix_format
        self.log_filter = log_filter
        self.source_filter = source_filter
        self.description_filter = description_filter
        self.quiet = quiet

        # Apply log filter to logs list
        if log_filter:
            self.logs = [log_filter]
            if not quiet:
                print(f"Log filter: {log_filter}")

        for log_name in self.logs:
            try:
                if not quiet:
                    print(f"Searching {log_name} log...")
                self._search_log(log_name, event_ids, start_time)
            except Exception as e:
                print(f"Error accessing {log_name} log: {e}")

        self._output_results(output_format)

    def _search_log(self, log_name, event_ids, start_time):
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
                        if event_time < start_time:
                            # If we've gone too far back, we can break
                            if events_checked > 1000:  # Limit to prevent infinite loops
                                break
                            continue
                        
                        # Check if this is one of our target Event IDs (or if we're in level_all mode)
                        if self.level_all or event.EventID in event_ids:
                            self._process_event(event, log_name)
                            matches_found += 1
                    
                    # If we've checked enough events or gone too far back, break
                    if events_checked > 1000:
                        break
                        
                except Exception as e:
                    if "No more data is available" in str(e):
                        break
                    else:
                        raise e
            
            if not self.quiet:
                print(f"  Checked {events_checked} events in {log_name} log, found {matches_found} matches")
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            if "A required privilege is not held by the client" in str(e):
                print(f"  {log_name} log: Access denied - requires elevated privileges")
                print(f"  Note: Security log requires 'SeSecurityPrivilege' even from elevated prompt")
            elif "Access is denied" in str(e):
                print(f"  {log_name} log: Access denied - insufficient privileges")
            else:
                print(f"Error reading {log_name} log: {e}")

    def _process_event(self, event, log_name):
        """Process and store event data"""
        try:
            # Get event level
            event_level = self._get_event_level(event.EventType)
            
            # Apply level filter if specified
            if self.level_filter and event_level != self.level_filter:
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

            event_data = {
                'timestamp': event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
                'log_name': log_name,
                'event_id': event.EventID,
                'level': event_level,
                'source': event.SourceName,
                'computer': event.ComputerName,
                'description': description,
                'category': self._get_event_category(event.EventID)
            }

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

    def _output_results(self, output_format):
        """Output results in the specified format"""
        if not self.results:
            print("No matching events found.")
            return

        if not self.quiet:
            print(f"\nFound {len(self.results)} matching events:")
            print("=" * 80)

        if self.matrix_format:
            self._output_matrix()
        elif output_format == 'json':
            print(json.dumps(self.results, indent=2, default=str))
        elif output_format == 'csv':
            self._output_csv()
        else:  # text format
            self._output_text()

    def _output_csv(self):
        """Output results in CSV format"""
        if not self.results:
            return

        # CSV header
        headers = ['timestamp', 'log_name', 'event_id', 'level',
                   'source', 'computer', 'category', 'description']
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
            print(f"\n[{i}] Event ID {event['event_id']} - {event['category']}")
            print(f"    Time: {event['timestamp']}")
            print(f"    Log: {event['log_name']}")
            print(f"    Level: {event['level']}")
            print(f"    Source: {event['source']}")
            print(f"    Computer: {event['computer']}")
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
        max_event_id = max(len(str(event['event_id'])) for event in self.results)
        
        # Set minimum widths and maximum for description
        time_width = max(19, max_time)  # YYYY-MM-DD HH:MM:SS
        log_width = max(8, max_log)
        level_width = max(11, max_level)
        source_width = min(25, max(max_source, 10))  # Limit source width
        event_id_width = max(8, max_event_id)
        desc_width = 50  # Fixed description width
        
        # Print header
        header = f"{'#':<3} {'Time':<{time_width}} {'Log':<{log_width}} {'Level':<{level_width}} {'Event ID':<{event_id_width}} {'Source':<{source_width}} {'Description':<{desc_width}}"
        print(header)
        print("=" * len(header))
        
        # Print data rows
        for i, event in enumerate(self.results, 1):
            # Truncate description if too long
            description = event['description'][:desc_width-3] + '...' if len(event['description']) > desc_width else event['description']
            description = description.replace('\n', ' ').replace('\r', ' ')  # Remove newlines
            
            # Truncate source if too long
            source = event['source'][:source_width-3] + '...' if len(event['source']) > source_width else event['source']
            
            row = f"{i:<3} {event['timestamp']:<{time_width}} {event['log_name']:<{log_width}} {event['level']:<{level_width}} {event['event_id']:<{event_id_width}} {source:<{source_width}} {description:<{desc_width}}"
            print(row)

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
            privilege = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
            
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


def search_threat_indicators(hours_back=24, output_format='text', specific_categories=None, level_filter=None, level_all=False, matrix_format=False, log_filter=None, source_filter=None, description_filter=None, quiet=False):
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
    searcher = WindowsEventLogSearcher()

    if level_all:
        # In level_all mode, we don't need specific Event IDs
        event_ids = []
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

    searcher.search_event_ids(event_ids, hours_back, output_format, level_filter, level_all, matrix_format, log_filter, source_filter, description_filter, quiet)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Windows Event Log Threat Hunting Tool')
    parser.add_argument('--hours', type=int, default=24,
                        help='Hours to look back (default: 24)')
    parser.add_argument(
        '--format', choices=['json', 'text', 'csv'], default='text', help='Output format')
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
    parser.add_argument('-o', '--output', type=str,
                        help='Write results to file (UTF-8). Incompatible with --matrix + non-text formats.')
    parser.add_argument(
        '--level', type=str, choices=['Error', 'Warning', 'Information', 'Critical', 'Verbose'], 
        help='Filter events by level (Error, Warning, Information, Critical, Verbose)')
    parser.add_argument(
        '--level-all', type=str, choices=['Error', 'Warning', 'Information', 'Critical', 'Verbose'], 
        help='Search for ALL events of specified level, ignoring Event ID filter')
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

    args = parser.parse_args()

    # Validate incompatible flags
    if args.matrix and args.format in ['json', 'csv']:
        print("Error: --matrix is incompatible with --format json/csv. Use --format text or omit --matrix.")
        sys.exit(2)

    # Load Event IDs configuration
    if args.config:
        EVENTS = load_event_ids_from_json(args.config)
        if EVENTS is None:
            print("Falling back to default Event IDs...")
            EVENTS = get_default_events()
    else:
        EVENTS = get_default_events()
    
    # Calculate all unique Event IDs
    ALL_EVENT_IDS = sorted({eid for cat in EVENTS.values() for eid in cat})
    
    print(f"Loaded {len(ALL_EVENT_IDS)} unique Event IDs from {len(EVENTS)} categories")

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
                    child_args = [script_path] + [a for a in sys.argv[1:] if a != '--elevate']
                    params = ' '.join([f'"{a}"' if ' ' in a or a.startswith('-') else a for a in child_args])
                    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                    if rc <= 32:
                        print("Failed to relaunch elevated. Please run this script from an elevated prompt.")
                        # If elevation failed, still show the warning unless suppressed
                        if not getattr(args, 'no-admin-warning', False):
                            print("WARNING: Administrator privileges not detected. This script works best when run elevated.")
                            print("Some logs (e.g., 'Security') and configuration actions may be inaccessible without elevation.")
                            print("Run from an elevated PowerShell or Command Prompt for full functionality.")
                    else:
                        # Successfully initiated elevation; exit current process
                        sys.exit(0)
                except Exception:
                    # On failure, show warning unless suppressed
                    if not getattr(args, 'no-admin-warning', False):
                        print("WARNING: Administrator privileges not detected. This script works best when run elevated.")
                        print("Some logs (e.g., 'Security') and configuration actions may be inaccessible without elevation.")
                        print("Run from an elevated PowerShell or Command Prompt for full functionality.")
            else:
                if not getattr(args, 'no-admin-warning', False):
                    print("WARNING: Administrator privileges not detected. This script works best when run elevated.")
                    print("Some logs (e.g., 'Security') and configuration actions may be inaccessible without elevation.")
                    print("Run from an elevated PowerShell or Command Prompt for full functionality.")
    except Exception:
        pass

    if args.list_categories:
        print("Available threat hunting categories:")
        for category, event_ids in EVENTS.items():
            print(f"  {category}: {len(event_ids)} Event IDs")
        sys.exit(0)

    if args.check_availability:
        searcher = WindowsEventLogSearcher()
        searcher.check_log_availability()
        sys.exit(0)

    if args.show_retention:
        searcher = WindowsEventLogSearcher()
        searcher.show_current_retention_settings()
        sys.exit(0)

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
        # Determine which level filter to use
        level_filter = args.level_all if args.level_all else args.level
        level_all = bool(args.level_all)
        
        def run_search(quiet=False):
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
                quiet=quiet
            )

        if args.output:
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
            run_search(quiet=False)
    except KeyboardInterrupt:
        print("\nSearch interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
