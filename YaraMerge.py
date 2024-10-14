import os
import tkinter as tk
from tkinter import filedialog, messagebox

def find_yara_files(root_dir):
    """
    Traverse through the root directory and its subdirectories to find all YARA files.
    """
    yara_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.endswith('.yara') or file.endswith('.yar'):
                yara_files.append(os.path.join(dirpath, file))
    return yara_files

def merge_yara_files(yara_files, output_file):
    """
    Merge the contents of all YARA files into a single master file, ensuring correct formatting
    with three spaces between each rule.
    """
    rule_names = set()
    with open(output_file, 'w') as master_file:
        master_file.write("// Merged YARA rules\n\n")
        for yara_file in yara_files:
            with open(yara_file, 'r') as f:
                rule_content = f.read()
                rules = rule_content.split("rule ")
                for rule in rules:
                    if rule.strip():
                        rule_header = rule.split("{")[0].strip()
                        rule_name = rule_header.split()[0]

                        if rule_name not in rule_names:
                            rule_names.add(rule_name)
                            # Write the rule and add three spaces after it
                            master_file.write("rule " + rule.strip() + "\n\n\n")
                        else:
                            print(f"Duplicate rule name '{rule_name}' found. Skipping...")

def select_directory():
    directory = filedialog.askdirectory()
    entry_directory.delete(0, tk.END)
    entry_directory.insert(0, directory)

def select_output_file():
    file = filedialog.asksaveasfilename(defaultextension=".yara",
                                        filetypes=[("YARA files", "*.yara")])
    entry_output.delete(0, tk.END)
    entry_output.insert(0, file)

def merge_files():
    root_directory = entry_directory.get()
    output_yara_file = entry_output.get()

    if not root_directory or not output_yara_file:
        messagebox.showerror("Error", "Please select both the root directory and output file.")
        return

    yara_files = find_yara_files(root_directory)
    if not yara_files:
        messagebox.showinfo("No Files Found", "No YARA files found in the specified directory.")
        return

    merge_yara_files(yara_files, output_yara_file)
    messagebox.showinfo("Success", f"Master YARA file created at: {output_yara_file}")

# GUI setup
root = tk.Tk()
root.title("YARA Merge")
root.geometry("500x300")
root.resizable(False, False)

# Directory selection
label_directory = tk.Label(root, text="Select Root Directory Containing Rules:")
label_directory.pack(pady=10)
entry_directory = tk.Entry(root, width=50)
entry_directory.pack(pady=5)
button_browse_directory = tk.Button(root, text="Browse", command=select_directory)
button_browse_directory.pack(pady=5)

# Output file selection
label_output = tk.Label(root, text="Select Output File Location & Name:")
label_output.pack(pady=10)
entry_output = tk.Entry(root, width=50)
entry_output.pack(pady=5)
button_browse_output = tk.Button(root, text="Browse", command=select_output_file)
button_browse_output.pack(pady=5)

# Merge button
button_merge = tk.Button(root, text="Merge YARA Files", command=merge_files, bg="#008CBA", fg="white")
button_merge.pack(pady=20)

# Run the application
root.mainloop()
