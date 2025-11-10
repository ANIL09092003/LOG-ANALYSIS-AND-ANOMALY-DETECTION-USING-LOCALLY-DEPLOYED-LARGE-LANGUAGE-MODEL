 
import csv
import re
import json

# File paths
input_file = r".\system_logs.txt"
output_file = r".\cleaned_system_logs.txt"

# Regex patterns for different log types
patterns = {
    "windows_event": re.compile(
        r"Event\s*ID:\s*(\d+)\s*\|\s*Source:\s*(.+?)\s*\|\s*Level:\s*(.+?)\s*\|\s*Time:\s*(.+?)\s*\|\s*Message:\s*(.*)",
        re.IGNORECASE
    ),
    "apache_access": re.compile(
        r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]+)" (\d{3}) (\S+)',
        re.IGNORECASE
    ),
    "syslog": re.compile(
        r"([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)"
    )
}

# Headers for each log type
headers = {
    "windows_event": ["Event ID", "Source", "Level", "Time", "Message"],
    "apache_access": ["IP", "Ident", "User", "DateTime", "Request", "Status", "Bytes"],
    "syslog": ["DateTime", "Host", "Process", "Message"],
    "json": None,  # will detect from keys
    "unknown": ["Raw Line"]
}

def detect_format(line):
    """Detect which log format the line matches."""
    # Try JSON first
    try:
        json.loads(line)
        return "json"
    except:
        pass

    for name, pattern in patterns.items():
        if pattern.search(line):
            return name
    return "unknown"

try:
    with open(input_file, "r") as infile:
        # Detect log type from first non-empty line
        first_line = ""
        for line in infile:
            if line.strip():
                first_line = line.strip()
                break

        log_type = detect_format(first_line)
        print(f"Detected log format: {log_type}")

        infile.seek(0)  # Go back to start
        with open(output_file, "w", newline='', encoding="utf-8") as outfile:
            writer = csv.writer(outfile)

            # Write header
            if log_type == "json":
                first_json = json.loads(first_line)
                writer.writerow(first_json.keys())
            else:
                writer.writerow(headers[log_type])

            # Process each line
            for line in infile:
                line = line.strip()
                if not line:
                    continue

                if log_type == "json":
                    try:
                        data = json.loads(line)
                        writer.writerow(data.values())
                    except json.JSONDecodeError:
                        print(f"Invalid JSON skipped: {line}")
                elif log_type in patterns:
                    match = patterns[log_type].search(line)
                    if match:
                        writer.writerow(match.groups())
                    else:
                        print(f"Line skipped (no match): {line}")
                else:  # Unknown format
                    writer.writerow([line])

    print(f"Logs parsed successfully. Output saved to {output_file}")

except FileNotFoundError:
    print(f"Error: Input file '{input_file}' not found.")

