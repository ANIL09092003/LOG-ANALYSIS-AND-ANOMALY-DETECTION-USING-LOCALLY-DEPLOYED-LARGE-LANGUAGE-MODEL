import re
import csv
import json
import sys
import requests
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ================== STEP 1: PREPROCESS RAW LOG FILE ==================
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

headers = {
    "windows_event": ["Event ID", "Source", "Level", "Time", "Message"],
    "apache_access": ["IP", "Ident", "User", "DateTime", "Request", "Status", "Bytes"],
    "syslog": ["DateTime", "Host", "Process", "Message"],
    "json": None,
    "unknown": ["Raw Line"]
}

def detect_format(line):
    try:
        json.loads(line)
        return "json"
    except:
        pass
    for name, pattern in patterns.items():
        if pattern.search(line):
            return name
    return "unknown"

def preprocess_logs(input_file, cleaned_file):
    with open(input_file, "r", encoding="utf-8", errors="ignore") as infile:
        first_line = ""
        for line in infile:
            if line.strip():
                first_line = line.strip()
                break

        log_type = detect_format(first_line)
        print(f"[+] Detected log format: {log_type}")

        infile.seek(0)
        with open(cleaned_file, "w", newline='', encoding="utf-8") as outfile:
            writer = csv.writer(outfile)

            if log_type == "json":
                first_json = json.loads(first_line)
                writer.writerow(first_json.keys())
            else:
                writer.writerow(headers[log_type])

            for line in infile:
                line = line.strip()
                if not line:
                    continue

                if log_type == "json":
                    try:
                        data = json.loads(line)
                        writer.writerow(data.values())
                    except json.JSONDecodeError:
                        continue
                elif log_type in patterns:
                    match = patterns[log_type].search(line)
                    if match:
                        writer.writerow(match.groups())
                else:
                    writer.writerow([line])

    print(f"[+] Logs parsed → {cleaned_file}")


# ================== STEP 2: MASK SENSITIVE DATA ==================
MASK_PATTERNS = {
    'IP_ADDRESS': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'EMAIL': re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    'USERNAME': re.compile(r'(?i)(User:|Username:|\\\\)([a-zA-Z0-9._-]+)'),
    'DOMAIN_USER': re.compile(r'(?i)([a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+)'),
    'URL': re.compile(r'(?i)(https?://[^\s<>"]+|www\.[^\s<>"]+)')
}

def mask_sensitive_data(text):
    masked_values = {}
    counter = 1
    for label, pattern in MASK_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            if value not in masked_values:
                masked_values[value] = f"MASKED_{label}_{counter}"
                counter += 1
    for orig, masked in sorted(masked_values.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(orig, masked)
    return text, masked_values

def mask_log_file(input_file, masked_file, mapping_file):
    with open(input_file, "r", encoding="utf-8", errors="ignore") as infile:
        data = infile.read()

    masked_data, mapping = mask_sensitive_data(data)

    with open(masked_file, "w", encoding="utf-8") as out:
        out.write(masked_data)
    with open(mapping_file, "w", encoding="utf-8") as mapout:
        json.dump(mapping, mapout, indent=4)

    print(f"[+] Masked log → {masked_file}")
    print(f"[+] Mapping → {mapping_file}")


# ================== STEP 3: ANALYSIS WITH LLM ==================
def stream_ollama(prompt, model="deepseek-r1:8b", host="http://127.0.0.1:11434"):
    url = f"{host}/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": True}
    proxies = {"http": None, "https": None}

    with requests.post(url, json=payload, stream=True, proxies=proxies) as response:
        if response.status_code != 200:
            raise Exception(f"Error {response.status_code}: {response.text}")

        for line in response.iter_lines():
            if line:
                data = json.loads(line.decode("utf-8"))
                if "response" in data:
                    yield data["response"]
                if data.get("done", False):
                    break

def analyze_logs(masked_file, output_file, console, model, host):
    with open(masked_file, "r", encoding="utf-8", errors="ignore") as f:
        log_content = f.read()

    prompt = f"""
You are a cybersecurity log analyst.
Analyze the following logs in detail.

For EACH line:
- Explain what it means
- Severity (Info/Warning/Error/Critical)
- Possible cause & risk
- Recommended action

Logs:
{log_content}
"""

    console.insert(tk.END, "\n[+] Sending logs to LLM...\n")
    console.see(tk.END)

    with open(output_file, "w", encoding="utf-8") as out:
        for chunk in stream_ollama(prompt, model=model, host=host):
            console.insert(tk.END, chunk)
            console.see(tk.END)
            console.update()
            out.write(chunk)

    console.insert(tk.END, f"\n\n[+] Full analysis saved → {output_file}\n")
    console.see(tk.END)


# ================== GUI APP ==================
class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Analysis with LLM")
        self.root.geometry("800x600")

        self.input_file = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.model = tk.StringVar(value="deepseek-r1:8b")
        self.host = tk.StringVar(value="http://127.0.0.1:11434")

        frm = tk.Frame(root)
        frm.pack(pady=10, fill="x")

        tk.Label(frm, text="Raw Log File:").grid(row=0, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.input_file, width=50).grid(row=0, column=1, padx=5)
        tk.Button(frm, text="Browse", command=self.browse_file).grid(row=0, column=2)

        tk.Label(frm, text="Output Folder:").grid(row=1, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.output_dir, width=50).grid(row=1, column=1, padx=5)
        tk.Button(frm, text="Browse", command=self.browse_folder).grid(row=1, column=2)

        tk.Label(frm, text="Model:").grid(row=2, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.model, width=30).grid(row=2, column=1, sticky="w")

        tk.Label(frm, text="Host:").grid(row=3, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.host, width=30).grid(row=3, column=1, sticky="w")

        self.console = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20)
        self.console.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Button(root, text="Run Pipeline", command=self.run_pipeline).pack(pady=5)

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt *.log *.csv"), ("All Files", "*.*")])
        if path:
            self.input_file.set(path)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.output_dir.set(path)

    def run_pipeline(self):
        if not self.input_file.get():
            messagebox.showerror("Error", "Select a log file first.")
            return
        if not self.output_dir.get():
            messagebox.showerror("Error", "Select an output folder.")
            return

        raw_log = self.input_file.get()
        out_dir = self.output_dir.get()

        cleaned = os.path.join(out_dir, "cleaned_logs.csv")
        masked = os.path.join(out_dir, "masked_logs.txt")
        mapping = os.path.join(out_dir, "mapping.json")
        analysis_out = os.path.join(out_dir, "analysis_output.txt")

        try:
            preprocess_logs(raw_log, cleaned)
            mask_log_file(cleaned, masked, mapping)
            analyze_logs(masked, analysis_out, self.console, self.model.get(), self.host.get())
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()

