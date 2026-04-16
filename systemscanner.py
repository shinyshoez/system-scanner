#!/usr/bin/env python3
# Author: Elmo Koo
# Date: Term 4 2025
# Purpose: Collect system information and save results to a CSV file

import os
import sys
import subprocess
import platform
import time
import uuid
import socket
import datetime
import importlib
import csv
import re
import warnings


# -------------------
# Constants and setup
# -------------------
# This section defines constants and file paths for the system scanner.
# It includes the modules required for Windows and Linux, the URL used for download speed testing,
# the directory where the script is located, and the CSV file for storing scan results.
WINDOWS_MODULES = ["psutil", "requests", "getmac"]
LINUX_MODULES = ["psutil", "requests"]
MACOS_MODULES = ["psutil", "requests"]
DOWNLOAD_URL = "https://speed.hetzner.de/100MB.bin"

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    SCRIPT_DIR = os.getcwd()

FILE_NAME = os.path.join(SCRIPT_DIR, "scan_results.csv")

HEADERS = [
    "Computer Name",
    "IP Address",
    "MAC Address",
    "Processor Model",
    "Operating System",
    "System Time",
    "Internet Connection Speed",
    "Active Ports"
]

# --------------
# Terminal Clear
# --------------
# This function clears the terminal window before running the system scan.
# On Windows, it executes the "cls" command, and on Linux/macOS, it executes the "clear" command.
def clearTerminal():
    os.system("cls" if platform.system() == "Windows" else "clear")

# ----------------------------------
# Dynamic module installation/import
# ----------------------------------
# Attempts to import the specified Python module.
# If the module is not installed, it automatically installs it via pip, then imports it and returns it.
def installAndImport(moduleName):
    try:
        try:
            return importlib.import_module(moduleName)
        except ImportError:
            print(f"Installing missing module: {moduleName}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", moduleName])
            return importlib.import_module(moduleName)
    except Exception as e:
        print(f"Failed to install/import module '{moduleName}': {e}")
        return None

# ----------------------------
# System information functions
# ----------------------------
# This section contains functions that retrieve system information.
# Each function returns a specific piece of information, such as computer name, IP address, or MAC address.

def getSystemTime():
    # Returns the current system time in dd/mm/yyyy HH:MM:SS format.
    try:
        return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return "N/A"

def getComputerName():
    # Returns the network name of the computer.
    try:
        return platform.node()
    except Exception:
        return "N/A"

def getLocalIp():
    # Returns the local IP address of the computer.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"[getLocalIp] Failed to get local IP: {e}")
        return "N/A"

def getWindowsMac():
    # Return the MAC address on Windows using getmac
    try:
        getmac_module = installAndImport("getmac")
        mac = None
        if getmac_module:
            try:
                mac = getmac_module.get_mac_address()
            except Exception as e:
                print(f"[getWindowsMac] getmac module failed internally: {e}")

        # Check if getmac returned a valid MAC, otherwise use uuid method
        if not mac:
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        return mac

    except Exception as e:
        print(f"[getWindowsMac] Failed to retrieve MAC address: {e}")
        return "N/A"

def getLinuxMac():
    # Returns the MAC address on Linux
    try:
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        return mac
    except Exception as e:
        print(f"[getLinuxMac] Failed to retrieve MAC address: {e}")
        return "N/A"
    
def getMacOsMAC():
    # Returns the MAC address on MacOS
    try:
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        return mac
    except Exception as e:
        print(f"[getMacOsMac] Failed to retrieve MAC address: {e}")
        return "N/A"

def getActivePorts():
    # Retrieves all local TCP ports with active (ESTABLISHED) connections.
    # Ignores listening or server-only ports.
    try:
        psutil = installAndImport("psutil")
        if psutil is None:
            return "N/A"

        ports = set()
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == "ESTABLISHED" and conn.laddr:
                ports.add(conn.laddr.port)

        return ";".join(map(str, sorted(ports))) if ports else "None"

    except Exception as e:
        print(f"[getActivePorts] Failed to retrieve host TCP ports: {e}")
        return "N/A"


def getDownloadSpeed(url=DOWNLOAD_URL):
    # Measures the download speed from the provided URL in Mb/s.
    try:
        requests = installAndImport("requests")
        if not requests:
            return "N/A"

        start = time.time()
        total_bytes = 0

        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            total_bytes = sum(len(chunk) for chunk in r.iter_content(131072))

        elapsed = time.time() - start
        if elapsed <= 0:
            return "N/A"

        # Convert bytes per second to megabits per second
        speed_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
        return f"{speed_mbps:.1f}Mb/s"

    except requests.exceptions.Timeout as e:
        print(f"[getDownloadSpeed] Timeout or slow server: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"[getDownloadSpeed] No internet connection: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[getDownloadSpeed] Network error: {e}")
    except Exception as e:
        print(f"[getDownloadSpeed] Unexpected error: {e}")

    return "N/A"

# -----------------------------
# OS and Processor helpers
# -----------------------------
# This section contains functions that retrieve processor and OS details.
# Logs the error and prints Error meesage if retrieval fails.

def getWindowsVersion():
    # Returns the Windows version of the computer.
    try:
        return f"Windows {platform.release()}"
    except Exception as e:
        print(f"[getWindowsVersion] Failed to get Windows version: {e}")
        return "Windows Unknown"

def getWindowsProcessor():
    # Returns the processor model for a Windows system.
    try:
        return platform.processor()
    except Exception as e:
        print(f"[getWindowsProcessor] Failed to get Windows processor: {e}")
        return "Unknown"

def getLinuxProcessor():
    # Returns the processor model for a Linux system.
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if "model name" in line:
                    return " ".join(line.split(":", 1)[1].strip().split()[:2])
    except Exception as e:
        print(f"[getLinuxProcessor] Failed to read CPU info: {e}")
    return platform.machine() or "Unknown"

def getLinuxOs():
    # Returns the Linux OS version of the computer.
    try:
        return f"Linux {platform.release().split('-')[0]}"
    except Exception as e:
        print(f"[getLinuxOs] Failed to get Linux OS version: {e}")
        return "Linux Unknown"

def getMacOsProcessor():
    # Returns the processor model for a MacOs system.
    try:
        result = subprocess.check_output(["sysctl", "-n",
                                          "machdep.cpu.brand_string"])
        return result.decode().strip()
    except Exception as e:
        print(f"[getMacOsProcessor] Failed to get processor: {e}")
    return platform.machine() or "Unknown"

def getMacOsVersion():
    # Returns the Os Version for a MacOs system. 
    try:
        release = platform.mac_ver()[0]
        return f"macOS {release}"
    except Exception as e:
        print(f"[getMacOsVersion] Failed to get macOS version: {e}")
        return "macOS Unknown"


# -----------------------------
# Sanitise function
# -----------------------------
# This function cleans the data before saving to CSV.
# It ensures that all values are strings and strips leading/trailing whitespace.
def sanitise(data):
    return [str(item or "N/A").strip() for item in data]

# ------------
# CSV handling
# ------------
# Saves the system scan results to a CSV file.
# Existing rows for the same computer are replaced with new data.
# New rows are appended if the computer is not already in the file.
# This ensures the CSV always contains the most recent information.

def updateOrAppendCsv(data):
    data = sanitise(data)
    rowDict = dict(zip(HEADERS, data))  # Map data to CSV headers
    rows = []

    if os.path.exists(FILE_NAME):
        with open(FILE_NAME, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                if r.get("Computer Name") == rowDict["Computer Name"]:
                    print(f"Duplicate found for '{rowDict['Computer Name']}'. Updating entry...")
                else:
                    rows.append(r)

    rows.append(rowDict)  # Add the new/updated row for the current computer

    with open(FILE_NAME, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()  # Write the header row first
        writer.writerows(rows)  # Write all rows to the CSV

    print(f"Results saved to '{FILE_NAME}'")  # Confirm that the file has been updated

# -------------
# Print Checker
# -------------
# Provides feedback to the user.
# Prints "Checking <label>..." before running the function.
# Prints "OK" if successful, "FAILED" otherwise.
# Adds a small delay after printing for smoother output.
# This allows the user to see which checks were successful.

def performCheck(label, func, delay=0.8):
    print(f"Checking {label}...", end=" ")
    try:
        result = func()
        if result != "N/A" and result != "":
            print("OK")
        else:
            print("FAILED")
        time.sleep(delay)  # small pause for smoother display
        return result
    except Exception:
        print("FAILED")
        time.sleep(delay)
        return "N/A"

# --------------------------
# Windows system scan branch
# --------------------------
# This function performs a system scan on a Windows computer.
# It installs any missing Windows modules, performs all system checks,
# and saves the results to the CSV file.
def windowsBranch():
    print("Running Windows system scan...")
    for m in WINDOWS_MODULES:
        installAndImport(m)

    row = [
        performCheck("Computer Name", getComputerName),
        performCheck("Local IP", getLocalIp),
        performCheck("MAC Address", getWindowsMac),
        performCheck("Processor", getWindowsProcessor),
        performCheck("Operating System", getWindowsVersion),
        performCheck("System Time", getSystemTime),
        performCheck("Download Speed", getDownloadSpeed),
        performCheck("Active Ports", getActivePorts)
    ]

    updateOrAppendCsv(row)

# ------------------------
# Linux system scan branch
# ------------------------
# This function performs a system scan on a Linux computer.
# It installs any missing Linux modules, performs all system checks,
# and saves the results to the CSV file.
def linuxBranch():
    print("Running Linux system scan...")
    for m in LINUX_MODULES:
        installAndImport(m)

    row = [
        performCheck("Computer Name", getComputerName),
        performCheck("Local IP", getLocalIp),
        performCheck("MAC Address", getLinuxMac),
        performCheck("Processor", getLinuxProcessor),
        performCheck("Operating System", getLinuxOs),
        performCheck("System Time", getSystemTime),
        performCheck("Download Speed", getDownloadSpeed),
        performCheck("Active Ports", getActivePorts)
    ]

    updateOrAppendCsv(row)

# ------------------------
# MacOs system scan branch
# ------------------------
# This function performs a system scan on a MacOS computer.
# It installs any missing MacOS modules, performs all system checks,
# and saves the results to the CSV file.
def macOsBranch():
    # Suppress urllib3 SSL warning on macOS due to LibreSSL incompatibility
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)                
    print("Running macOS system scan...") 
    for m in MACOS_MODULES:
        installAndImport(m)
    row = [
        performCheck("Computer Name", getComputerName),
        performCheck("Local IP", getLocalIp),
        performCheck("MAC Address", getMacOsMAC),
        performCheck("Processor", getMacOsProcessor),
        performCheck("Operating System", getMacOsVersion),
        performCheck("System Time", getSystemTime),
        performCheck("Download Speed", getDownloadSpeed),
        performCheck("Active Ports", getActivePorts) 
    ]   

    updateOrAppendCsv(row)

# -------------
# Main function
# -------------
# It clears the terminal, detects the operating system,
# and runs the corresponding system scan branch.
# If the operating system is unsupported, it prints an error and exits.
def main():
    clearTerminal()
    system = platform.system()
    print(f"Detected OS: {system}")
    if system == "Windows":
        windowsBranch()
    elif system == "Linux":
        linuxBranch()
    elif system == "Darwin":
        macOsBranch()
    else:
        print(f"Unsupported platform: {system}")
        sys.exit(1)

if __name__ == "__main__":
    main()
