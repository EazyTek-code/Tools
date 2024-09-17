import os
import sqlite3
import winreg
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue
from datetime import datetime

# File System Mapping
def map_file_system(root_directories, progress_queue):
    files = []

    def map_directory(directory):
        dir_files = []
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    dir_files.append((filepath, os.path.getsize(filepath), os.path.getmtime(filepath)))
                except FileNotFoundError:
                    continue
                except PermissionError:
                    continue
        return dir_files

    total_directories = len(root_directories)
    with ThreadPoolExecutor() as executor:
        future_to_directory = {executor.submit(map_directory, root_dir): root_dir for root_dir in root_directories}
        for i, future in enumerate(as_completed(future_to_directory), start=1):
            try:
                dir_files = future.result()
                files.extend(dir_files)
                progress = (i / total_directories) * 50  # 50% progress for file system mapping
                progress_queue.put((progress, f"Mapping file system: {future_to_directory[future]}"))
            except Exception as e:
                print(f"Error mapping directory {future_to_directory[future]}: {e}")

    return files

# Registry Mapping
def map_registry(progress_queue):
    hives = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
    }

    all_keys = []

    def map_hive(hive_name, hive):
        return map_registry_hive(hive_name, hive)

    total_hives = len(hives)
    with ThreadPoolExecutor() as executor:
        future_to_hive = {executor.submit(map_hive, hive_name, hive): hive_name for hive_name, hive in hives.items()}
        for i, future in enumerate(as_completed(future_to_hive), start=1):
            try:
                hive_keys = future.result()
                all_keys.extend(hive_keys)
                progress = 50 + (i / total_hives) * 50  # 50% to 100% progress for registry mapping
                progress_queue.put((progress, f"Mapping registry: {future_to_hive[future]}"))
            except Exception as e:
                print(f"Error mapping registry hive {future_to_hive[future]}: {e}")

    return all_keys

def map_registry_hive(hive_name, hive):
    keys = []
    try:
        with winreg.OpenKey(hive, '') as key:
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                subkey_path = f"{hive_name}\\{subkey_name}"
                keys.append(subkey_path)
                keys.extend(map_registry_keys(hive, subkey_name, hive_name))
    except OSError:
        pass
    except PermissionError:
        pass
    return keys

def map_registry_keys(hive, reg_path, hive_name):
    keys = []
    try:
        with winreg.OpenKey(hive, reg_path) as key:
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                subkey_path = f"{reg_path}\\{subkey_name}"
                keys.append(f"{hive_name}\\{subkey_path}")
                keys.extend(map_registry_keys(hive, subkey_path, hive_name))
    except OSError:
        pass
    except PermissionError:
        pass
    return keys

# Save to Database
def save_to_database(database_path, file_data, registry_data):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS file_system
                      (path TEXT PRIMARY KEY, size INTEGER, modified_time REAL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS registry
                      (path TEXT PRIMARY KEY)''')
    
    cursor.executemany('INSERT OR REPLACE INTO file_system VALUES (?, ?, ?)', file_data)
    cursor.executemany('INSERT OR REPLACE INTO registry VALUES (?)', [(r,) for r in registry_data])
    
    conn.commit()
    conn.close()

# Compare Databases
def compare_databases(db1_path, db2_path):
    conn1 = sqlite3.connect(db1_path)
    conn2 = sqlite3.connect(db2_path)
    cursor1 = conn1.cursor()
    cursor2 = conn2.cursor()
    
    changes = {
        'added_files': [],
        'removed_files': [],
        'modified_files': [],
        'added_registry_keys': [],
        'removed_registry_keys': []
    }
    
    # Compare file system
    cursor1.execute('SELECT path, size, modified_time FROM file_system')
    files1 = {row[0]: row for row in cursor1.fetchall()}
    
    cursor2.execute('SELECT path, size, modified_time FROM file_system')
    files2 = {row[0]: row for row in cursor2.fetchall()}
    
    for path, data in files2.items():
        if path not in files1:
            changes['added_files'].append(data)
        elif files1[path][1:] != data[1:]:
            changes['modified_files'].append(data)
    
    for path in files1:
        if path not in files2:
            changes['removed_files'].append(files1[path])
    
    # Compare registry
    cursor1.execute('SELECT path FROM registry')
    reg_keys1 = set(row[0] for row in cursor1.fetchall())
    
    cursor2.execute('SELECT path FROM registry')
    reg_keys2 = set(row[0] for row in cursor2.fetchall())
    
    changes['added_registry_keys'] = list(reg_keys2 - reg_keys1)
    changes['removed_registry_keys'] = list(reg_keys1 - reg_keys2)
    
    conn1.close()
    conn2.close()
    
    return changes

# Generate HTML Report
def generate_html_report(changes, filename):
    # Basic HTML structure with CSS and JavaScript for interactivity and filtering
    html_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>System Changes Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
            }
            h1 {
                text-align: center;
                color: #333;
            }
            h2 {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                cursor: pointer;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            .content {
                padding: 0 15px;
                display: none;
                border-left: 3px solid #4CAF50;
                margin-bottom: 20px;
            }
            .content table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            .content table, .content th, .content td {
                border: 1px solid #ccc;
            }
            .content th, .content td {
                padding: 10px;
                text-align: left;
            }
            #filter-input {
                width: 50%;
                padding: 10px;
                margin: 20px auto;
                display: block;
                font-size: 16px;
                text-align: center;
            }
            .filterable {
                margin-top: 10px;
                background-color: #f9f9f9;
            }
        </style>
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                var headers = document.querySelectorAll("h2");
                headers.forEach(function(header) {
                    header.addEventListener("click", function() {
                        var content = this.nextElementSibling;
                        content.style.display = content.style.display === "block" ? "none" : "block";
                    });
                });
                
                document.getElementById('filter-input').addEventListener('input', function() {
                    var filter = this.value.toLowerCase();
                    var rows = document.querySelectorAll('.filterable tbody tr');
                    rows.forEach(function(row) {
                        var text = row.textContent.toLowerCase();
                        row.style.display = text.includes(filter) ? '' : 'none';
                    });
                });
            });
        </script>
    </head>
    <body>
        <h1>System Changes Report</h1>
        <input type="text" id="filter-input" placeholder="Filter for specific files or processes...">
    '''

    # Rest of the function remains unchanged...

    def add_section(title, changes_list):
        section = f'<h2>{title}</h2>\n<div class="content">\n'
        if not changes_list:
            section += '<p>No changes detected.</p>\n'
        else:
            section += '<table class="filterable">\n<tr><th>Path</th><th>Details</th></tr>\n'
            for change in changes_list:
                path = change[0]
                details = f"Size: {change[1]}, Modified: {change[2]}"
                section += f'<tr><td>{path}</td><td>{details}</td></tr>\n'
            section += '</table>\n'
        section += '</div>\n'
        return section

    # Add file changes sections
    html_content += add_section("Added Files", changes['added_files'])
    html_content += add_section("Removed Files", changes['removed_files'])
    html_content += add_section("Modified Files", changes['modified_files'])

    # Add registry changes sections
    def add_registry_section(title, registry_keys):
        section = f'<h2>{title}</h2>\n<div class="content">\n'
        if not registry_keys:
            section += '<p>No changes detected.</p>\n'
        else:
            section += '<table class="filterable">\n<tr><th>Registry Key</th></tr>\n'
            for key in registry_keys:
                section += f'<tr><td>{key}</td></tr>\n'
            section += '</table>\n'
        section += '</div>\n'
        return section

    html_content += add_registry_section("Added Registry Keys", changes['added_registry_keys'])
    html_content += add_registry_section("Removed Registry Keys", changes['removed_registry_keys'])

    # End of HTML
    html_content += '''
    </body>
    </html>
    '''

    # Write the HTML content to the file
    with open(filename, 'w') as file:
        file.write(html_content)

# GUI Update to Include HTML Generation
class SystemMapperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("System Mapper")
        self.root.configure(bg='light blue')  # Set background color

        # Style for modern look
        style = ttk.Style()
        style.configure('TButton', font=('Arial', 12, 'bold'))
        style.configure('TLabel', font=('Arial', 12))

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=10, fill=tk.X)

        # Progress Label
        self.progress_label = ttk.Label(root, text="Progress: 0%", style='TLabel')
        self.progress_label.pack()

        # Buttons with modern style
        self.map_button = ttk.Button(root, text="Map System", command=self.map_system, style='TButton')
        self.map_button.pack(pady=10)

        self.compare_button = ttk.Button(root, text="Compare Databases", command=self.compare_databases, style='TButton')
        self.compare_button.pack(pady=10)

        self.report_button = ttk.Button(root, text="Generate HTML Report", command=self.generate_html_report, style='TButton')
        self.report_button.pack(pady=10)

        # Text Area for Output
        self.output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30, bg='white')
        self.output_text.pack(pady=10)

        # Variables to store data
        self.file_data = []
        self.registry_data = []
        self.changes = {}

        # Queue for progress updates
        self.progress_queue = queue.Queue()

    def update_progress(self):
        while not self.progress_queue.empty():
            progress, message = self.progress_queue.get()
            self.progress_var.set(progress)
            self.progress_label.config(text=f"Progress: {int(progress)}% - {message}")
            self.root.update_idletasks()

    def map_system(self):
        self.output_text.insert(tk.END, "Starting system mapping...\n")
        self.progress_var.set(0)
        self.progress_label.config(text="Progress: 0%")
        self.root.update_idletasks()

        def map_worker():
            root_directories = ['C:\\']  # Adjust path as needed
            self.file_data = map_file_system(root_directories, self.progress_queue)  # Multi-threaded
            self.registry_data = map_registry(self.progress_queue)  # Multi-threaded
            self.progress_queue.put((100, "Mapping complete"))
            self.update_progress()

            # Save to database automatically
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            db_filename = f"system_map_{timestamp}.db"
            save_to_database(db_filename, self.file_data, self.registry_data)
            self.output_text.insert(tk.END, f"Data saved to {db_filename}\n")

        threading.Thread(target=map_worker).start()
        self.root.after(100, self.check_queue)

    def check_queue(self):
        self.update_progress()
        if self.progress_var.get() < 100:
            self.root.after(100, self.check_queue)
        else:
            self.output_text.insert(tk.END, "Mapping complete.\n")

    def compare_databases(self):
        db1_path = filedialog.askopenfilename(filetypes=[("Database files", "*.db")])
        db2_path = filedialog.askopenfilename(filetypes=[("Database files", "*.db")])
        
        if db1_path and db2_path:
            self.changes = compare_databases(db1_path, db2_path)
            self.output_text.insert(tk.END, f"Comparison complete.\n")

    def generate_html_report(self):
        if not self.changes:
            messagebox.showwarning("Warning", "No changes to report. Please compare databases first.")
            return
        
        html_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if html_path:
            generate_html_report(self.changes, html_path)
            self.output_text.insert(tk.END, f"HTML report generated at {html_path}\n")

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    gui = SystemMapperGUI(root)
    root.mainloop()
