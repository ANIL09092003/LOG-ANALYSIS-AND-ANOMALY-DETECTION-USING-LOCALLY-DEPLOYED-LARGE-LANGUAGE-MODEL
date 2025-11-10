import requests
import json
import os

os.environ["NO_PROXY"] = "localhost,127.0.0.1,192.168.111.202"

def stream_ollama(prompt, model="deepseek-r1:8b"):
    url = "http://192.168.111.202:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": True   # streaming mode
    }

    # Disable proxies explicitly
    proxies = {"http": None, "https": None}

    with requests.post(url, json=payload, stream=True, proxies=proxies) as response:
        if response.status_code != 200:
            raise Exception(f"Error {response.status_code}: {response.text}")
        
        # Read streamed JSON chunks
        for line in response.iter_lines():
            if line:
                data = json.loads(line.decode("utf-8"))
                if "response" in data:
                    print(data["response"], end="", flush=True)
                if data.get("done", False):
                    break


if __name__ == "__main__":
    # Read Windows log file (plain text export from Event Viewer, .txt or .log)
    log_file = "F:\Students\AnilKalyan\masked_logs.txt"

    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            log_content = f.read()
    except Exception as e:
        print(f"Error reading log file: {e}")
        exit(1)

    # Build the analysis prompt
    prompt = f"""You are a system analyst. 
The following is a Windows system log file content. 
Please analyze it and highlight any abnormalities, critical errors, warnings, or suspicious activity.

Log file content:
{log_content}
"""
    #prompt = f"""What is the capital of India"""
    
    print("Prompt to LLM:")
    print(prompt)
    print("DeepSeek R1 says:\n")
    stream_ollama(prompt)
    print("\n\n--- Done ---")
