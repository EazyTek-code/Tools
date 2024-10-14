import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import json
import re

# File to store user preferences
CONFIG_FILE = 'config.json'

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:  # Open in read mode
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}  # Return an empty dictionary if the file is empty or corrupted
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file)

def browse_yara_binary():
    file_path = filedialog.askopenfilename(title="Select YARA Binary", filetypes=[("Executable Files", "*.exe;*.bin;*.out"), ("All Files", "*.*")])
    yara_binary_entry.delete(0, tk.END)
    yara_binary_entry.insert(0, file_path)
    config['yara_binary'] = file_path
    save_config(config)

def browse_rule_file():
    file_path = filedialog.askopenfilename(title="Select YARA Rule File", filetypes=[("YARA Files", "*.yar;*.yara"), ("All Files", "*.*")])
    rule_file_entry.delete(0, tk.END)
    rule_file_entry.insert(0, file_path)
    config['rule_file'] = file_path
    save_config(config)

def browse_target_directory():
    directory_path = filedialog.askdirectory(title="Select Directory to Scan")
    target_directory_entry.delete(0, tk.END)
    target_directory_entry.insert(0, directory_path)
    config['target_directory'] = directory_path
    save_config(config)

def log_message(message):
    activity_text.configure(state='normal')
    activity_text.insert(tk.END, message + "\n")
    activity_text.configure(state='disabled')
    activity_text.see(tk.END)

def run_yara_scan():
    yara_binary = yara_binary_entry.get()
    rule_file = rule_file_entry.get()
    target_directory = target_directory_entry.get()

    if not yara_binary or not rule_file or not target_directory:
        messagebox.showwarning("Input Error", "Please select the YARA binary, a YARA rule file, and a target directory.")
        return

    def scan():
        log_message("Starting YARA scan...")
        yara_command = [f'"{yara_binary}"', '-r', '-s', f'"{rule_file}"', f'"{target_directory}"']

        try:
            result = subprocess.run(" ".join(yara_command), capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                output = result.stdout
                if output.strip():
                    log_message("Scan complete. Generating reports...")
                    generate_combined_report(output, target_directory)
                    rules = extract_yara_rules_with_action(rule_file)
                    generate_statistics_report(output, target_directory, rules)
                    log_message("Reports generated successfully.")
                else:
                    messagebox.showinfo("Scan Complete", "No matches found.")
                    log_message("Scan complete. No matches found.")
            else:
                log_message(f"YARA error: {result.stderr}")
                messagebox.showerror("Error", result.stderr)
        except Exception as e:
            log_message(f"Exception: {e}")
            messagebox.showerror("Error", str(e))

    threading.Thread(target=scan, daemon=True).start()

def generate_combined_report(output, target_directory):
    # Define the HTML structure with dark background, green buttons, and white text
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>YARA Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #1A1A1A; color: #FFFFFF; }
            h1 { text-align: center; color: #FFFFFF; font-weight: bold; }
            .container { margin-bottom: 20px; padding: 10px; border: 1px solid #333; border-radius: 5px; background-color: #262626; }
            .search-box { margin-bottom: 20px; text-align: center; }
            .search-box input { width: 80%; padding: 10px; margin: 10px 0; box-sizing: border-box; border: none; border-radius: 4px; background-color: #333; color: #FFFFFF; }
            .header { font-size: 1.2em; color: #FFFFFF; font-weight: bold; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center; }
            .details { margin-left: 20px; display: none; }
            .detection-strings { margin-left: 40px; margin-top: 5px; color: #B0BEC5; font-family: monospace; }
            .toggle-btn, .toggle-all-btn { cursor: pointer; background-color: #4CAF50; border: none; border-radius: 3px; padding: 5px 10px; color: #1A1A1A; font-weight: bold; margin: 5px; }
            .toggle-btn:hover, .toggle-all-btn:hover { background-color: #45A049; }
        </style>
        <script>
            function filterReport() {
                var input, filter, containers, match, i, txtValue;
                input = document.getElementById('searchInput');
                filter = input.value.toUpperCase();
                containers = document.getElementsByClassName('container');

                for (i = 0; i < containers.length; i++) {
                    match = containers[i];
                    txtValue = match.textContent || match.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        match.style.display = '';
                    } else {
                        match.style.display = 'none';
                    }
                }
            }

            function toggleDetails(id) {
                var details = document.getElementById(id);
                if (details.style.display === "none") {
                    details.style.display = "block";
                } else {
                    details.style.display = "none";
                }
            }

            function toggleAllDetails(action) {
                var details = document.getElementsByClassName('details');
                for (var i = 0; i < details.length; i++) {
                    details[i].style.display = action === 'expand' ? 'block' : 'none';
                }
            }
        </script>
    </head>
    <body>
        <h1>YARA Scan Report</h1>
        <div class="search-box">
            <input type="text" id="searchInput" onkeyup="filterReport()" placeholder="Search for matches, folders, or files...">
        </div>
        <button class="toggle-all-btn" onclick="toggleAllDetails('expand')">Expand All</button>
        <button class="toggle-all-btn" onclick="toggleAllDetails('collapse')">Collapse All</button>
    """

    matches = {}
    report_data = {}
    total_files = 0
    total_detections = 0

    for line in output.splitlines():
        if not line.startswith("0x"):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                rule_name = parts[0]
                file_path = parts[1]
                if file_path not in matches:
                    matches[file_path] = {}
                matches[file_path][rule_name] = []
        else:
            if matches:
                last_file_path = list(matches.keys())[-1]
                last_rule = list(matches[last_file_path].keys())[-1]
                matches[last_file_path][last_rule].append(line.strip())

    for root, dirs, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            folder = root
            if folder not in report_data:
                report_data[folder] = {
                    'file_count': 0,
                    'detected_files': [],
                    'undetected_files': []
                }

            report_data[folder]['file_count'] += 1
            total_files += 1
            if file_path in matches:
                report_data[folder]['detected_files'].append(file_path)
                total_detections += 1
            else:
                report_data[folder]['undetected_files'].append(file_path)

    total_missed = total_files - total_detections
    html_content += f"""
    <div class="container">
        <div class="header">Scan Summary</div>
        <div class="details" style="display: block;">
            Total Files Scanned: {total_files}<br>
            Total Positive Detections: {total_detections}<br>
            Total Missed Detections: {total_missed}
        </div>
    </div>
    """

    folder_id = 0
    for folder, data in report_data.items():
        folder_id += 1
        html_content += f"""
        <div class="container">
            <div class="header">
                <span>Folder: {folder}</span>
                <button class="toggle-btn" onclick="toggleDetails('folder-{folder_id}')">Toggle</button>
            </div>
            <div class="details" id="folder-{folder_id}">
                Total Files: {data['file_count']}<br>
                Positive Detections: {len(data['detected_files'])}<br>
                Missed Detections: {len(data['undetected_files'])}
                <div class="detection-strings">
                    <br><h3>Detected Files:</h3><br>
        """
        for detected_file in data['detected_files']:
            html_content += f"{detected_file}<br>"

        html_content += "<br><h3><strong>Files without YARA match:</h3><br>"
        for undetected_file in data['undetected_files']:
            html_content += f"{undetected_file}<br>"

        html_content += "</div></div></div>"

    match_id = 0
    for file_path, rules in matches.items():
        for rule_name, detections in rules.items():
            match_id += 1
            html_content += f"""
            <div class="container">
                <div class="header">
                    <span>Rule: {rule_name} - File: {file_path}</span>
                    <button class="toggle-btn" onclick="toggleDetails('match-{match_id}')">Toggle</button>
                </div>
                <div class="details" id="match-{match_id}">
                    <div class="detection-strings">
            """
            for detection in detections:
                html_content += f"{detection}<br>"
            html_content += "</div></div></div>"

    html_content += "</body></html>"

    with open('yara_combined_report.html', 'w', encoding='utf-8') as report_file:
        report_file.write(html_content)

    messagebox.showinfo("Report Generated", "The YARA combined scan report has been generated as 'yara_combined_report.html'.")

def generate_statistics_report(output, target_directory, rules):
    total_files = 0
    total_detections = 0
    detection_summary = {}

    matches = {}
    for line in output.splitlines():
        if not line.startswith("0x"):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                rule_name = parts[0]
                file_path = parts[1]
                if file_path not in matches:
                    matches[file_path] = {}
                matches[file_path][rule_name] = []
                total_detections += 1
                if rule_name not in detection_summary:
                    detection_summary[rule_name] = 0
                detection_summary[rule_name] += 1

    for root, dirs, files in os.walk(target_directory):
        total_files += len(files)

    total_missed = total_files - total_detections

    stats_content = f"""
    YARA Scan Statistics Report
    ---------------------------
    Target Directory: {target_directory}
    Total Files Scanned: {total_files}
    Total Positive Detections: {total_detections}
    Total Missed Detections: {total_missed}
    --------------------------------
    Detection Summary by Rule:
    """

    for rule, count in detection_summary.items():
        stats_content += f"  Rule: {rule} - Detections: {count}\n"

    stats_content += "\n--------------------------------\nAvailable Rules in the Rule File:\n"
    for rule_name, action, _ in rules:
        stats_content += f"  {rule_name} (Action: {action})\n"

    with open('yara_statistics_report.txt', 'w') as stats_file:
        stats_file.write(stats_content)

    log_message("Statistics report saved as 'yara_statistics_report.txt'.")

def extract_yara_rules_with_action(rule_file):
    rules = []
    try:
        with open(rule_file, 'r') as file:
            current_rule = None
            action = None
            rule_text = []
            for line in file:
                rule_match = re.match(r'rule\s+(\w+)', line)
                action_match = re.search(r'Action\s*=\s*"(R|T)"', line)

                if rule_match:
                    if current_rule:
                        rules.append((current_rule, action if action else "Unknown", "\n".join(rule_text)))
                    current_rule = rule_match.group(1)
                    action = None  # Reset action for the new rule
                    rule_text = [line.strip()]  # Start collecting rule text

                if action_match:
                    action = action_match.group(1)

                if current_rule:
                    rule_text.append(line.strip())

            if current_rule:
                rules.append((current_rule, action if action else "Unknown", "\n".join(rule_text)))

    except Exception as e:
        log_message(f"Error reading YARA rule file: {e}")
    return rules

# Load or initialize configuration
config = load_config()

root = tk.Tk()
root.title("YaraRunner")
root.geometry("600x500")

mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.pack(fill=tk.BOTH, expand=True)

yara_binary_label = ttk.Label(mainframe, text="YARA Binary Path:")
yara_binary_label.grid(row=0, column=0, sticky=tk.W)
yara_binary_entry = ttk.Entry(mainframe, width=50)
yara_binary_entry.grid(row=0, column=1)
browse_yara_binary_button = ttk.Button(mainframe, text="Browse", command=browse_yara_binary)
browse_yara_binary_button.grid(row=0, column=2)

rule_file_label = ttk.Label(mainframe, text="YARA Rule File:")
rule_file_label.grid(row=1, column=0, sticky=tk.W)
rule_file_entry = ttk.Entry(mainframe, width=50)
rule_file_entry.grid(row=1, column=1)
browse_rule_button = ttk.Button(mainframe, text="Browse", command=browse_rule_file)
browse_rule_button.grid(row=1, column=2)

target_directory_label = ttk.Label(mainframe, text="Target Directory:")
target_directory_label.grid(row=2, column=0, sticky=tk.W)
target_directory_entry = ttk.Entry(mainframe, width=50)
target_directory_entry.grid(row=2, column=1)
browse_target_button = ttk.Button(mainframe, text="Browse", command=browse_target_directory)
browse_target_button.grid(row=2, column=2)

run_scan_button = ttk.Button(mainframe, text="Run YARA Scan", command=run_yara_scan)
run_scan_button.grid(row=3, column=1, pady=10)

activity_label = ttk.Label(mainframe, text="Activity Log:")
activity_label.grid(row=4, column=0, sticky=tk.W)
activity_text = scrolledtext.ScrolledText(mainframe, width=70, height=10, state='disabled')
activity_text.grid(row=5, column=0, columnspan=3, pady=10)

if 'yara_binary' in config:
    yara_binary_entry.insert(0, config['yara_binary'])
if 'rule_file' in config:
    rule_file_entry.insert(0, config['rule_file'])
if 'target_directory' in config:
    target_directory_entry.insert(0, config['target_directory'])

root.mainloop()
