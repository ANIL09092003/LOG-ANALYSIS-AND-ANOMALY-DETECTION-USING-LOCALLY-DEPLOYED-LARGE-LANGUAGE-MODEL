import requests
import sys

def analyze_logs(log_file):
    # Read your log file
    with open(log_file, "r", encoding="utf-8") as f:
        logs = f.read()

    # Ask Ollama to analyze and return structured text
    prompt = f"""
You are a security log analyst. Analyze the following Windows log file
and give a structured text report with these sections:

Summary:
Total log lines:
Failed Logins:
Successful Logins:
Suspicious Activities:
Critical Errors:
Recommendations:

Logs:
{logs}
"""

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama2",   # change to your model, e.g. "deepseek-r1:8b"
            "prompt": prompt
        }
    )

    # Collect response text
    result = ""
    for line in response.iter_lines():
        if line:
            data = line.decode("utf-8")
            if '"response"' in data:
                result += data.split('"response":"')[1].split('"')[0]

    return result.strip()


if _name_ == "_main_":
    if len(sys.argv) < 2:
        print("Usage: python analyze_and_save.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    analysis = analyze_logs(log_file)

    # Always save to TXT
    with open("analysis_output.txt", "w", encoding="utf-8") as f:
        f.write(analysis)

    print("✅ Analysis completed. Results saved in 'analysis_output.txt'")