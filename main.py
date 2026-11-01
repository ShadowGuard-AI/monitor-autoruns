import argparse
import logging
import os
import sys
import time

try:
    import winreg  # Windows-specific registry access
except ImportError:
    print("Error: this tool runs on Windows only, because the winreg module is not available on this platform.")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for registry locations and startup folders
REGISTRY_LOCATIONS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    # The two Winlogon entries in this list are values inside a
    # shared key, not keys of their own. I enumerate every value
    # in that key, so changes to unrelated Winlogon values are
    # reported as autorun changes alongside Userinit and Shell.
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
]

STARTUP_FOLDERS = [
    os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"  # Check for existence before using
]

# Both hives are monitored: the current user hive and the machine
# hive, whose Run and RunOnce entries apply to every user.
REGISTRY_HIVES = [
    (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
    (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
]


def setup_argparse():
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(description="Monitors changes to autorun locations for malware persistence.")
    parser.add_argument("-i", "--interval", type=int, default=60,
                        help="Interval in seconds to check for changes. Default is 60 seconds.")
    parser.add_argument("-l", "--log_file", type=str, default="autorun_monitor.log",
                        help="Path to the log file. Default is autorun_monitor.log")
    parser.add_argument("-r", "--report_file", type=str, default="autorun_report.txt",
                        help="Path to the report file. Default is autorun_report.txt")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    return parser.parse_args()


def get_registry_autoruns_status(location, hive=None):
    """
    Retrieves autorun entries from a specified registry location, with
    a read status that keeps an unreadable location distinct from a
    location that was read and found empty.

    Args:
        location (str): The registry key location to check.
        hive: The registry hive to open the location under. Defaults
              to HKEY_CURRENT_USER.

    Returns:
        A tuple (entries, status, reason). status is "read" when the
        location was opened and enumerated, or "missing",
        "permission", or "error" when it could not be read, with a
        short reason. entries is empty in both the read-and-empty and
        the unreadable cases; status is what tells them apart.
    """
    if hive is None:
        hive = winreg.HKEY_CURRENT_USER
    autoruns = {}
    try:
        key = winreg.OpenKey(hive, location, 0, winreg.KEY_READ) # Added permission
    except FileNotFoundError:
        logging.warning(f"Registry location not found: {location}")
        return {}, "missing", "key not found"
    except PermissionError:
        logging.error(f"Permission denied accessing registry location: {location}")
        return {}, "permission", "permission denied"
    except Exception as e:
        logging.error(f"Error accessing registry location {location}: {e}")
        return {}, "error", str(e)

    try:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                autoruns[name] = value
                i += 1
            # Any OSError ends the enumeration, not only the end of
            # values signal. An error partway through gives me a shorter
            # state for this cycle, and the comparison in the monitor
            # loop reads the missing tail as removed entries.
            except OSError:  # No more values
                break
    finally:
        winreg.CloseKey(key)
    return autoruns, "read", ""


def get_registry_autoruns(location, hive=None):
    """
    Retrieves autorun entries from a specified registry location.

    Returns:
        dict: A dictionary containing the name and data of each autorun entry.
              Returns an empty dictionary if the location doesn't exist or cannot be accessed.
    """
    autoruns, _status, _reason = get_registry_autoruns_status(location, hive)
    return autoruns

def get_startup_folder_autoruns_status(folder):
    """
    Retrieves autorun entries from a specified startup folder, with a
    read status that keeps an unreadable or missing folder distinct
    from a folder that was read and found empty.

    Returns:
        A tuple (entries, status, reason). entries is a sorted list,
        so comparisons never depend on directory listing order.
    """
    if not os.path.exists(folder):
        logging.warning(f"Startup folder not found: {folder}")
        return [], "missing", "folder not found"

    autoruns = []
    try:
        for filename in os.listdir(folder):
            filepath = os.path.join(folder, filename)
            if os.path.isfile(filepath):  # Only list files
                # A startup entry is recorded by path alone. Editing the
                # file, or retargeting a shortcut in place, leaves my state
                # identical, where a registry entry changing its data is
                # caught because registry states carry values. The two
                # halves of this monitor watch with different depth.
                autoruns.append(filepath)
    except OSError as e:
        logging.error(f"Error accessing startup folder {folder}: {e}")
        return [], "error", str(e)
    except Exception as e:
        logging.error(f"Unexpected error accessing startup folder {folder}: {e}")
        return [], "error", str(e)

    return sorted(autoruns), "read", ""


def get_startup_folder_autoruns(folder):
    """
    Retrieves autorun entries from a specified startup folder.

    Returns:
        list: A sorted list of files in the startup folder.
              Returns an empty list if the folder doesn't exist or cannot be accessed.
    """
    autoruns, _status, _reason = get_startup_folder_autoruns_status(folder)
    return autoruns


def monitor_autoruns(interval, log_file, report_file, verbose):
    """
    Monitors autorun locations for changes and logs any detected modifications.

    Args:
        interval (int): The interval in seconds between checks.
        log_file (str): The path to the log file.
        report_file (str): The path to the report file.
        verbose (bool): Enable verbose output to the console.
    """

    # Setup file logger
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)  # Set level for file logging
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logging.getLogger('').addHandler(file_handler) # Added handler

    if verbose:
        logging.getLogger('').setLevel(logging.DEBUG)  # Set logger level to DEBUG when verbose is True
        logging.info("Verbose output enabled.")
    else:
         logging.getLogger('').setLevel(logging.INFO)


    def read_registry_states():
        """Reads every registry location in both hives, keeping the
        coverage (which locations were read, and which could not be
        read and why) separate from the entry states."""
        states = {}
        unreadable = []
        read_count = 0
        entry_count = 0
        for hive, hive_name in REGISTRY_HIVES:
            for location in REGISTRY_LOCATIONS:
                label = f"{hive_name}\\{location}"
                entries, status, reason = get_registry_autoruns_status(location, hive)
                states[label] = entries
                if status == "read":
                    read_count += 1
                    entry_count += len(entries)
                else:
                    unreadable.append(f"{label} ({status}: {reason})")
        return states, read_count, entry_count, unreadable

    def read_startup_states():
        states = {}
        unreadable = []
        read_count = 0
        for folder in STARTUP_FOLDERS:
            entries, status, reason = get_startup_folder_autoruns_status(folder)
            states[folder] = entries
            if status == "read":
                read_count += 1
            else:
                unreadable.append(f"{folder} ({status}: {reason})")
        return states, read_count, unreadable

    def log_coverage(when, reg_read, reg_entries, reg_unreadable, folder_read, folder_unreadable):
        # Coverage counts both hives against the same location list,
        # and neither hive is opened with an explicit 32 or 64 bit
        # view. On a 64 bit system the separate Wow6432Node autorun
        # locations are not in my list, so a 32 bit program's Run
        # entry is outside the count I report.
        total_locations = len(REGISTRY_HIVES) * len(REGISTRY_LOCATIONS)
        logging.info(
            f"Coverage {when}: registry locations read {reg_read} of {total_locations} "
            f"({reg_entries} entries); registry locations that could not be read: "
            f"{reg_unreadable if reg_unreadable else 'none'}; startup folders read "
            f"{folder_read} of {len(STARTUP_FOLDERS)}; startup folders that could not be read: "
            f"{folder_unreadable if folder_unreadable else 'none'}."
        )
        if reg_read == 0 and folder_read == 0:
            logging.warning("Coverage warning: no autorun location could be read; the monitor is watching nothing it can verify.")

    previous_registry_states, reg_read, reg_entries, reg_unreadable = read_registry_states()
    previous_startup_folder_states, folder_read, folder_unreadable = read_startup_states()

    logging.info("Initial autorun states captured.")
    log_coverage("at startup", reg_read, reg_entries, reg_unreadable, folder_read, folder_unreadable)

    while True:
        try:
            time.sleep(interval)
            logging.debug(f"Checking for autorun changes after {interval} seconds...")

            report_lines = []  # Accumulate changes for the report

            # Check Registry Changes
            current_registry_states, reg_read, reg_entries, reg_unreadable = read_registry_states()
            for label in previous_registry_states:
                current_state = current_registry_states[label]
                previous_state = previous_registry_states[label]
                # Polling sets the limit of what I can see: a change that is
                # made and reverted between two cycles never existed as far
                # as my states are concerned, and a change made while the
                # monitor is stopped is folded silently into the next
                # baseline whenever it restarts.
                if current_state != previous_state:
                    logging.warning(f"Autorun changes detected in registry location: {label}")

                    added = set(current_state.keys()) - set(previous_state.keys())
                    removed = set(previous_state.keys()) - set(current_state.keys())
                    modified = set(current_state.keys()) & set(previous_state.keys())

                    for name in sorted(added):
                        line = f"Added registry entry in {label}: {name} = {current_state[name]}"
                        logging.info(line)
                        report_lines.append(line)
                    for name in sorted(removed):
                        line = f"Removed registry entry in {label}: {name} (last value: {previous_state[name]})"
                        logging.info(line)
                        report_lines.append(line)
                    if modified:
                        for key in modified:
                            if current_state[key] != previous_state[key]:
                                logging.info(f"Modified registry entry in {label}: {key} (Old: {previous_state[key]}, New: {current_state[key]})")
                                report_lines.append(f"Modified registry entry in {label}: {key} (Old: {previous_state[key]}, New: {current_state[key]})")

                    previous_registry_states[label] = current_state


            # Check Startup Folder Changes. States are sorted lists, so
            # a pure reordering of the same files is not a change.
            current_startup_states, folder_read, folder_unreadable = read_startup_states()
            for folder in STARTUP_FOLDERS:
                current_state = current_startup_states[folder]
                if sorted(current_state) != sorted(previous_startup_folder_states[folder]):
                    logging.warning(f"Autorun changes detected in startup folder: {folder}")

                    added = set(current_state) - set(previous_startup_folder_states[folder])
                    removed = set(previous_startup_folder_states[folder]) - set(current_state)

                    if added:
                        logging.info(f"Added files in startup folder {folder}: {added}")
                        report_lines.append(f"Added files in startup folder {folder}: {added}")
                    if removed:
                        logging.info(f"Removed files in startup folder {folder}: {removed}")
                        report_lines.append(f"Removed files in startup folder {folder}: {removed}")

                    previous_startup_folder_states[folder] = current_state

            log_coverage("this cycle", reg_read, reg_entries, reg_unreadable, folder_read, folder_unreadable)


            # Write report to file if changes were detected.
            if report_lines:
                try:
                    with open(report_file, "a") as f:  # Append to file
                        f.write("\n".join(report_lines) + "\n")  # Ensure newlines for each entry
                    logging.info(f"Changes written to report file: {report_file}")
                except IOError as e:
                    logging.error(f"Error writing to report file: {e}")


        except KeyboardInterrupt:
            logging.info("Monitoring stopped by user.")
            break
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")


def main():
    """Main function to execute the autorun monitoring."""
    args = setup_argparse()
    if args.interval <= 0:
        logging.error("Interval must be a positive number of seconds.")
        sys.exit(1)
    monitor_autoruns(args.interval, args.log_file, args.report_file, args.verbose)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Run with default settings:  python main.py
# 2. Run with a 30-second interval: python main.py -i 30
# 3. Run with verbose output and custom log file: python main.py -v -l my_monitor.log
# 4. Run with a custom report file and interval: python main.py -r my_report.txt -i 120