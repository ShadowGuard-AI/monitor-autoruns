import argparse
import logging
import os
import time
import psutil
import winreg  # Windows-specific registry access

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for registry locations and startup folders
REGISTRY_LOCATIONS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
]

STARTUP_FOLDERS = [
    os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"  # Check for existence before using
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


def get_registry_autoruns(location):
    """
    Retrieves autorun entries from a specified registry location.

    Args:
        location (str): The registry key location to check.

    Returns:
        dict: A dictionary containing the name and data of each autorun entry.
              Returns an empty dictionary if the location doesn't exist or cannot be accessed.
    """
    autoruns = {}
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, location, 0, winreg.KEY_READ) # Added permission
    except FileNotFoundError:
        logging.warning(f"Registry location not found: {location}")
        return {}
    except PermissionError:
        logging.error(f"Permission denied accessing registry location: {location}")
        return {}
    except Exception as e:
        logging.error(f"Error accessing registry location {location}: {e}")
        return {}

    try:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                autoruns[name] = value
                i += 1
            except OSError:  # No more values
                break
    finally:
        winreg.CloseKey(key)
    return autoruns

def get_startup_folder_autoruns(folder):
    """
    Retrieves autorun entries from a specified startup folder.

    Args:
        folder (str): The path to the startup folder.

    Returns:
        list: A list of files in the startup folder.
              Returns an empty list if the folder doesn't exist or cannot be accessed.
    """
    autoruns = []
    if not os.path.exists(folder):
        logging.warning(f"Startup folder not found: {folder}")
        return []

    try:
        for filename in os.listdir(folder):
            filepath = os.path.join(folder, filename)
            if os.path.isfile(filepath):  # Only list files
                autoruns.append(filepath)
    except OSError as e:
        logging.error(f"Error accessing startup folder {folder}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error accessing startup folder {folder}: {e}")
        return []

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


    previous_registry_states = {}
    previous_startup_folder_states = {}

    for location in REGISTRY_LOCATIONS:
        previous_registry_states[location] = get_registry_autoruns(location)

    for folder in STARTUP_FOLDERS:
        if os.path.exists(folder): # only monitor if path exist
            previous_startup_folder_states[folder] = get_startup_folder_autoruns(folder)
        else:
            previous_startup_folder_states[folder] = []

    logging.info("Initial autorun states captured.")

    while True:
        try:
            time.sleep(interval)
            logging.debug(f"Checking for autorun changes after {interval} seconds...")

            report_lines = []  # Accumulate changes for the report

            # Check Registry Changes
            for location in REGISTRY_LOCATIONS:
                current_state = get_registry_autoruns(location)
                if current_state != previous_registry_states[location]:
                    logging.warning(f"Autorun changes detected in registry location: {location}")

                    added = set(current_state.keys()) - set(previous_registry_states[location].keys())
                    removed = set(previous_registry_states[location].keys()) - set(current_state.keys())
                    modified = set(current_state.keys()) & set(previous_registry_states[location].keys())

                    if added:
                        logging.info(f"Added registry entries in {location}: {added}")
                        report_lines.append(f"Added registry entries in {location}: {added}")
                    if removed:
                        logging.info(f"Removed registry entries in {location}: {removed}")
                        report_lines.append(f"Removed registry entries in {location}: {removed}")
                    if modified:
                        for key in modified:
                            if current_state[key] != previous_registry_states[location][key]:
                                logging.info(f"Modified registry entry in {location}: {key} (Old: {previous_registry_states[location][key]}, New: {current_state[key]})")
                                report_lines.append(f"Modified registry entry in {location}: {key} (Old: {previous_registry_states[location][key]}, New: {current_state[key]})")

                    previous_registry_states[location] = current_state


            # Check Startup Folder Changes
            for folder in STARTUP_FOLDERS:
                if os.path.exists(folder):
                    current_state = get_startup_folder_autoruns(folder)
                    if current_state != previous_startup_folder_states[folder]:
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
                else:
                    if previous_startup_folder_states[folder]: # If folder existed and now it doesnt
                        logging.warning(f"Startup folder {folder} has been removed or is inaccessible.")
                        report_lines.append(f"Startup folder {folder} has been removed or is inaccessible.")
                        previous_startup_folder_states[folder] = []


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
    monitor_autoruns(args.interval, args.log_file, args.report_file, args.verbose)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Run with default settings:  python autorun_monitor.py
# 2. Run with a 30-second interval: python autorun_monitor.py -i 30
# 3. Run with verbose output and custom log file: python autorun_monitor.py -v -l my_monitor.log
# 4. Run with a custom report file and interval: python autorun_monitor.py -r my_report.txt -i 120