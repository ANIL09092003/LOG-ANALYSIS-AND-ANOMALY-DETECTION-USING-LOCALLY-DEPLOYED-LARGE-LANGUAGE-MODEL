import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import os
import json
import re
import requests
import sys
from io import StringIO

# Masking patterns from mask_code.py
PATTERNS = {
    'IP_ADDRESS': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'EMAIL': re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    'USERNAME': re.compile(r'(?i)(User:|Username:|\\\\)([a-zA-Z0-9._-]+)'),
    'DOMAIN_USER': re.compile(r'(?i)([a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+)'),  
    'SID': re.compile(r'(S-\d+-\d+-\d+-\d+-\d+-\d+)'),  
    'SERVER_NAME': re.compile(r'(?i)(Server(Name)?:\s*)([a-zA-Z0-9._-]+)'),
    'DNS_NAME': re.compile(r'(?i)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'),  
    'DOMAIN': re.compile(r'(?i)(Domain(Name)?:\s*)([a-zA-Z0-9.-]+)'),
    'FILE_PATH': re.compile(r'(?i)([A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)'),
    'UNC_PATH': re.compile(r'(?i)(\\\\[^\\/:*?"<>|\r\n]+\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)'),
    'URL': re.compile(r'(?i)(https?://[^\s<>"]+|www\.[^\s<>"]+)'),
    'GUID': re.compile(r'(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
    'MAC_ADDRESS': re.compile(r'(?i)([0-9A-F]{2}[:-]){5}([0-9A-F]{2})'),
    'COMPUTER_NAME': re.compile(r'(?i)(Computer(Name)?:\s*)([a-zA-Z0-9._-]+)'),
    'HOSTNAME': re.compile(r'(?i)(Host(Name)?:\s*)([a-zA-Z0-9._-]+)'),
    'PROCESS_ID': re.compile(r'(?i)(PID|Process ID):\s*(\d+)'),
    'SESSION_ID': re.compile(r'(?i)(Session ID):\s*(\d+)'),
    'ACCOUNT_NAME': re.compile(r'(?i)(Account(Name)?:\s*)([a-zA-Z0-9._-]+)'),
    'CERTIFICATE': re.compile(r'(?i)(Certificate|Cert):\s*([A-F0-9]+)'),
    'REGISTRY_KEY': re.compile(r'(?i)(HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*)'),
    'WORKSTATION': re.compile(r'(?i)(Workstation(Name)?:\s*)([a-zA-Z0-9._-]+)'),
    'CLSID': re.compile(r'(?i)(CLSID\s+)({[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}})'),
    'APPID': re.compile(r'(?i)(APPID\s+)({[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}})'),
    'DEVICE_ID': re.compile(r'(?i)(USB|PCI)\\[^\\]+'),  
    'PROCESS_PATH': re.compile(r'(?i)(Process: \')([^\']+)(\')'),  
}

def mask_sensitive_data(text):
    masked_values = {}
    counter = 1

    # First pass: Find all sensitive data
    for label, pattern in PATTERNS.items():
        if label in ['USERNAME', 'SERVER_NAME', 'DNS_NAME', 'DOMAIN', 'COMPUTER_NAME', 
                     'HOSTNAME', 'PROCESS_ID', 'SESSION_ID', 'ACCOUNT_NAME', 'WORKSTATION']:
            # These patterns have groups
            for match in pattern.finditer(text):
                groups = match.groups()
                if len(groups) >= 2:  # Ensure there are enough groups
                    value = groups[-1]  # Use the last group as the value to mask
                    if value and value not in masked_values:
                        masked_values[value] = f'MASKED_{label}_{counter}'
                        counter += 1
        elif label in ['DOMAIN_USER', 'SID', 'DNS_NAME', 'GUID', 'CLSID', 'APPID', 'DEVICE_ID']:
            # Patterns that capture the entire value
            for match in pattern.finditer(text):
                value = match.group(0)  # Use the full match
                if value and value not in masked_values:
                    masked_values[value] = f'MASKED_{label}_{counter}'
                    counter += 1
        elif label == 'PROCESS_PATH':
            # Special handling for process paths
            for match in pattern.finditer(text):
                value = match.group(2)  # The path part
                if value and value not in masked_values:
                    masked_values[value] = f'MASKED_{label}_{counter}'
                    counter += 1
        else:
            # For other patterns
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[0] if len(match) == 1 else match[-1]  # Use first or last item if tuple
                else:
                    value = match
                if value and value not in masked_values:
                    masked_values[value] = f'MASKED_{label}_{counter}'
                    counter += 1

    # Second pass: Replace all sensitive data
    # Sort by length in descending order to avoid partial replacements
    for original, masked in sorted(masked_values.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(original, masked)  # original is now a string from masked_values

    return text, masked_values

# From analyze_and_save.py, adapted
def call_ollama(prompt, model="deepseek-r1:8b"):
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": True},
            timeout=180
        )
        if response.status_code == 200:
            full_response = ""
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    if "response" in data:
                        full_response += data["response"]
                    if data.get("done", False):
                        break
            return full_response.strip()
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Ollama error: {e}"

def fallback_analysis(lines):
    text = "".join(lines)
    total_lines = len(lines)
    failed_logins = len(re.findall(r"failed login|logon failure", text, re.IGNORECASE))
    errors = len(re.findall(r"error", text, re.IGNORECASE))
    warnings = len(re.findall(r"warn", text, re.IGNORECASE))
    access_denied = len(re.findall(r"access denied", text, re.IGNORECASE))

    summary = [
        "⚡ Fallback Local Analysis (no LLaMA):",
        f"Total log lines: {total_lines}",
        f"Failed logins: {failed_logins}",
        f"Errors: {errors}",
        f"Warnings: {warnings}",
        f"Access Denied: {access_denied}",
    ]
    return "\n".join(summary)

def analyze_logs(log_content, output_callback):
    lines = log_content.splitlines(keepends=True)
    chunk_size = 100
    results = []

    for i in range(0, len(lines), chunk_size):
        chunk = "".join(lines[i:i+chunk_size])
        prompt = f"""
Analyze these Windows log entries and summarize key security issues clearly:

{chunk}
"""
        output_callback(f"⏳ Processing lines {i+1} to {min(i+chunk_size, len(lines))}...")
        result = call_ollama(prompt)

        if result.startswith("Ollama error") or result.startswith("Error:"):
            result = fallback_analysis(lines[i:i+chunk_size])

        results.append(f"\n--- Analysis for lines {i+1}-{min(i+chunk_size, len(lines))} ---\n{result}")
    
    return "\n\n".join(results)

# GUI Class
class LogAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Log File Analyzer")
        
        self.file_path = tk.StringVar()
        
        tk.Label(root, text="Select Raw Log File:").pack(pady=10)
        tk.Entry(root, textvariable=self.file_path, width=50).pack()
        tk.Button(root, text="Browse", command=self.browse_file).pack()
        
        tk.Button(root, text="Process Log", command=self.start_processing).pack(pady=10)
        
        self.output_text = scrolledtext.ScrolledText(root, width=80, height=20)
        self.output_text.pack(pady=10)
        
        self.processing = False

    def browse_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("Log files", "*.log")])
        if file:
            self.file_path.set(file)

    def start_processing(self):
        if self.processing:
            messagebox.showwarning("Warning", "Processing already in progress.")
            return
        
        input_file = self.file_path.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid log file.")
            return
        
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Starting processing...\n")
        self.processing = True
        
        threading.Thread(target=self.process_log, args=(input_file,)).start()

    def process_log(self, input_file):
        try:
            # Step 1: Read log
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            self.update_output("Log file read successfully.\n")
            
            # Step 2: Mask sensitive data
            masked_content, mapping = mask_sensitive_data(log_content)
            self.update_output("Sensitive data masked.\n")
            
            # Save masked log and mapping (optional, in same dir)
            base_dir = os.path.dirname(input_file)
            masked_file = os.path.join(base_dir, "masked_logs.txt")
            mapping_file = os.path.join(base_dir, "mapping.json")
            with open(masked_file, 'w', encoding='utf-8') as f:
                f.write(masked_content)
            with open(mapping_file, 'w', encoding='utf-8') as f:
                json.dump(mapping, f, indent=4)
            self.update_output(f"Masked log saved to: {masked_file}\nMapping saved to: {mapping_file}\n")
            
            # Step 3: Analyze with LLM
            analysis_result = analyze_logs(masked_content, self.update_output)
            self.update_output("Analysis completed.\n")
            self.update_output(analysis_result + "\n")
            
            # Save analysis output
            analysis_file = os.path.join(base_dir, "analysis_output.txt")
            with open(analysis_file, 'w', encoding='utf-8') as f:
                f.write(analysis_result)
            self.update_output(f"Analysis saved to: {analysis_file}\n")
        
        except Exception as e:
            self.update_output(f"Error: {str(e)}\n")
        
        finally:
            self.processing = False

    def update_output(self, message):
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.root.update_idletasks()

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerGUI(root)
    root.mainloop()