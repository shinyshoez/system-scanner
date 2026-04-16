# System Scanner

A Python tool built as part of my cybersecurity course on automating processes, designed to collect information on computers and save the results to a CSV file.

## What it does

Scans the local machine and records:

- Computer name
- Local IP address
- MAC address
- Processor model
- Operating system
- System time
- Internet download speed
- Active TCP ports

Results are saved to `scan_results.csv` in the same folder. If the same computer is scanned again, its entry is updated rather than duplicated.

## Requirements

- Python 3
- Windows, Linux, or macOS
- Internet connection (for download speed test)

The script will automatically install any missing Python modules:
- `psutil`
- `requests`
- `getmac` (Windows only)

## How to run

```bash
python3 systemscanner.py
```

On Windows:

```bash
python systemscanner.py
```

## Output

Results are saved to `scan_results.csv` with the following columns:

| Column | Description |
|---|---|
| Computer Name | Network hostname of the machine |
| IP Address | Local IP address |
| MAC Address | Hardware MAC address |
| Processor Model | CPU model name |
| Operating System | OS name and version |
| System Time | Date and time of the scan |
| Internet Connection Speed | Download speed in Mb/s |
| Active Ports | Active TCP ports separated by semicolons |

## Changing the download URL

The download speed test uses a default file hosted on GitHub. You can change it by editing the `DOWNLOAD_URL` constant at the top of `systemscanner.py`:

```python
DOWNLOAD_URL = "https://your-preferred-url-here"
```

For best results, use a server geographically close to you.

## Notes

- On macOS, run with `sudo` to allow active port scanning:
  ```bash
  sudo python3 systemscanner.py
  ```
- The script requires permission to read network connections for port scanning

## Author

Elmo Koo — Cybersecurity Student
