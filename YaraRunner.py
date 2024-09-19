import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

def browse_yara_binary():
    file_path = filedialog.askopenfilename(title="Select Path To your YARA Binary", filetypes=[("Executable Files", "*.exe;*.bin;*.out"), ("All Files", "*.*")])
    yara_binary_entry.delete(0, tk.END)
    yara_binary_entry.insert(0, file_path)

def browse_rule_file():
    file_path = filedialog.askopenfilename(title="Select YARA Rule File", filetypes=[("YARA Files", "*.yar;*.yara"), ("All Files", "*.*")])
    rule_file_entry.delete(0, tk.END)
    rule_file_entry.insert(0, file_path)

def browse_target_directory():
    directory_path = filedialog.askdirectory(title="Select Directory to Scan")
    target_directory_entry.delete(0, tk.END)
    target_directory_entry.insert(0, directory_path)

def run_yara_scan():
    yara_binary = yara_binary_entry.get()
    rule_file = rule_file_entry.get()
    target_directory = target_directory_entry.get()
    
    if not yara_binary or not rule_file or not target_directory:
        messagebox.showwarning("Input Error", "Please select the YARA binary, a YARA rule file, and a target directory.")
        return

    # Command to execute YARA
    yara_command = [yara_binary, '-s', '-r', rule_file, target_directory]

    try:
        # Run the YARA binary as a subprocess
        result = subprocess.run(yara_command, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Process the output
            output = result.stdout
            if output.strip():  # Check if there is any output
                generate_report(output)
            else:
                messagebox.showinfo("Scan Complete", "No matches found.")
        else:
            # If YARA returns an error
            messagebox.showerror("Error", result.stderr)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def generate_report(output):
    # Define the HTML structure with advanced styling and JavaScript filtering
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>YARA Scan Report</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                background-color: #121212; 
                color: #e0e0e0; 
            }
            h1 { text-align: center; color: #ffa500; }
            .search-box { 
                margin-bottom: 20px; 
                text-align: center; 
            }
            .search-box input {
                width: 80%;
                padding: 10px;
                margin: 10px 0;
                box-sizing: border-box;
                border: none;
                border-radius: 4px;
                background-color: #2e2e2e;
                color: #e0e0e0;
            }
            .match-container {
                margin-bottom: 20px;
                padding: 10px;
                border: 1px solid #444;
                border-radius: 5px;
                background-color: #1e1e1e;
            }
            .match-header {
                font-size: 1.2em;
                color: #ffa500;
                margin-bottom: 5px;
            }
            .match-details {
                margin-left: 20px;
            }
            .detection-strings {
                margin-left: 40px;
                margin-top: 5px;
                color: #b0b0b0;
                font-family: monospace;
            }
            .no-match {
                text-align: center;
                color: #ff5722;
            }
        </style>
        <script>
            function filterMatches() {
                var input, filter, containers, match, i, txtValue;
                input = document.getElementById('searchInput');
                filter = input.value.toUpperCase();
                containers = document.getElementsByClassName('match-container');

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
        </script>
    </head>
    <body>
        <h1>YARA Scan Report</h1>
        <div class="search-box">
            <input type="text" id="searchInput" onkeyup="filterMatches()" placeholder="Search for matches...">
        </div>
    """

    # Parse the YARA output and generate the HTML for each detection
    if output.strip():
        # Assuming the output format for each match is:
        # "rule_name file_path\nstring_output"
        current_rule = ""
        current_file = ""
        detection_strings = []

        for line in output.splitlines():
            if not line.startswith('0x'):  # If the line does not start with an offset, it's a new rule
                if current_rule and detection_strings:
                    # Create a container for the previous detection
                    html_content += f"""
                    <div class="match-container">
                        <div class="match-header">Rule: {current_rule}</div>
                        <div class="match-details">File: {current_file}</div>
                        <div class="detection-strings">
                    """
                    for detection in detection_strings:
                        html_content += f"{detection}<br>"
                    html_content += "</div></div>"

                # Start a new rule detection
                parts = line.split(maxsplit=1)
                if len(parts) >= 2:
                    current_rule = parts[0]
                    current_file = parts[1]
                    detection_strings = []
            else:
                # This is a detection string, add it to the list
                detection_strings.append(line.strip())

        # Add the last parsed rule if there is any
        if current_rule and detection_strings:
            html_content += f"""
            <div class="match-container">
                <div class="match-header">Rule: {current_rule}</div>
                <div class="match-details">File: {current_file}</div>
                <div class="detection-strings">
            """
            for detection in detection_strings:
                html_content += f"{detection}<br>"
            html_content += "</div></div>"

    else:
        html_content += '<div class="no-match">No matches found.</div>'

    # Closing the HTML tags
    html_content += """
    </body>
    </html>
    """

    # Write the HTML content to a file
    with open('yara_scan_report.html', 'w', encoding='utf-8') as report_file:
        report_file.write(html_content)

    messagebox.showinfo("Report Generated", "The YARA scan report has been generated as 'yara_scan_report.html'.")

# Setting up the main GUI window
root = tk.Tk()
root.title("YARA File Detection Tool")
root.geometry("500x300")

# Create a frame to hold the elements with padding for a modern look
mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.pack(fill=tk.BOTH, expand=True)

# YARA Binary Path
yara_binary_label = ttk.Label(mainframe, text="YARA Binary Path:")
yara_binary_label.grid(row=0, column=0, sticky=tk.W)
yara_binary_entry = ttk.Entry(mainframe, width=50)
yara_binary_entry.grid(row=0, column=1)
browse_yara_binary_button = ttk.Button(mainframe, text="Browse", command=browse_yara_binary)
browse_yara_binary_button.grid(row=0, column=2)

# YARA Rule File
rule_file_label = ttk.Label(mainframe, text="YARA Rule File:")
rule_file_label.grid(row=1, column=0, sticky=tk.W)
rule_file_entry = ttk.Entry(mainframe, width=50)
rule_file_entry.grid(row=1, column=1)
browse_rule_button = ttk.Button(mainframe, text="Browse", command=browse_rule_file)
browse_rule_button.grid(row=1, column=2)

# Target Directory
target_directory_label = ttk.Label(mainframe, text="Target Directory:")
target_directory_label.grid(row=2, column=0, sticky=tk.W)
target_directory_entry = ttk.Entry(mainframe, width=50)
target_directory_entry.grid(row=2, column=1)
browse_target_button = ttk.Button(mainframe, text="Browse", command=browse_target_directory)
browse_target_button.grid(row=2, column=2)

# Run Scan Button
run_scan_button = ttk.Button(mainframe, text="Run YARA Scan", command=run_yara_scan)
run_scan_button.grid(row=3, column=1, pady=10)

root.mainloop()
