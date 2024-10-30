import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

def find_files(directory, search_string, file_extension=None):
    files_found = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file_extension and not file.endswith(file_extension):
                continue
            
            file_path = os.path.join(root, file)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                continue

            if search_string in content:
                files_found.append(file_path)
    return files_found

def replace_in_files(files_to_modify, search_string, replace_string):
    for file_path in files_to_modify:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            new_content = content.replace(search_string, replace_string)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"Replaced '{search_string}' with '{replace_string}' in: {file_path}")
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")

def browse_directory():
    directory = filedialog.askdirectory()
    if directory:
        entry_directory.delete(0, tk.END)
        entry_directory.insert(0, directory)

def scan_for_files():
    directory = entry_directory.get()
    search_string = entry_search.get()
    file_extension = entry_extension.get().strip() or None
    
    if not directory or not search_string:
        messagebox.showerror("Error", "Please fill in all required fields.")
        return
    
    files_found = find_files(directory, search_string, file_extension)
    
    if files_found:
        listbox_files.delete(0, tk.END)
        for file in files_found:
            listbox_files.insert(tk.END, file)
    else:
        messagebox.showinfo("No Files Found", "No files containing the search string were found.")

def execute_replace():
    selected_indices = listbox_files.curselection()
    if not selected_indices:
        messagebox.showerror("Error", "No files selected for replacement.")
        return
    
    files_to_modify = [listbox_files.get(i) for i in selected_indices]
    search_string = entry_search.get()
    replace_string = entry_replace.get()
    
    replace_in_files(files_to_modify, search_string, replace_string)
    messagebox.showinfo("Success", "Replacement operation completed successfully.")
    listbox_files.delete(0, tk.END)

# GUI Setup
app = tk.Tk()
app.title("Find and Replace Tool")
app.geometry("700x550")

# Set style for a modern look
style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Arial', 10), padding=5)
style.configure('TEntry', padding=5)
style.configure('TLabel', font=('Arial', 10), padding=5)

# Directory Selection
frame_directory = ttk.Frame(app, padding="10")
frame_directory.pack(fill='x', pady=5)
label_directory = ttk.Label(frame_directory, text="Directory:")
label_directory.grid(row=0, column=0, sticky='w')
entry_directory = ttk.Entry(frame_directory, width=50)
entry_directory.grid(row=0, column=1, padx=5)
btn_browse = ttk.Button(frame_directory, text="Browse", command=browse_directory)
btn_browse.grid(row=0, column=2)

# Search String
frame_search = ttk.Frame(app, padding="10")
frame_search.pack(fill='x', pady=5)
label_search = ttk.Label(frame_search, text="String to search for:")
label_search.grid(row=0, column=0, sticky='w')
entry_search = ttk.Entry(frame_search, width=50)
entry_search.grid(row=0, column=1, padx=5)

# Replacement String
frame_replace = ttk.Frame(app, padding="10")
frame_replace.pack(fill='x', pady=5)
label_replace = ttk.Label(frame_replace, text="Replacement string:")
label_replace.grid(row=0, column=0, sticky='w')
entry_replace = ttk.Entry(frame_replace, width=50)
entry_replace.grid(row=0, column=1, padx=5)

# File Extension (Optional)
frame_extension = ttk.Frame(app, padding="10")
frame_extension.pack(fill='x', pady=5)
label_extension = ttk.Label(frame_extension, text="File extension filter (optional):")
label_extension.grid(row=0, column=0, sticky='w')
entry_extension = ttk.Entry(frame_extension, width=50)
entry_extension.grid(row=0, column=1, padx=5)

# Listbox for displaying files
frame_files = ttk.Frame(app, padding="10")
frame_files.pack(fill='both', expand=True, pady=10)
label_files = ttk.Label(frame_files, text="Files containing the search string:")
label_files.pack(anchor='w')
scrollbar_files = ttk.Scrollbar(frame_files, orient='vertical')
listbox_files = tk.Listbox(frame_files, width=80, height=10, selectmode=tk.MULTIPLE, yscrollcommand=scrollbar_files.set, font=('Arial', 10))
scrollbar_files.config(command=listbox_files.yview)
scrollbar_files.pack(side='right', fill='y')
listbox_files.pack(side='left', fill='both', expand=True)

# Buttons
frame_buttons = ttk.Frame(app, padding="10")
frame_buttons.pack(pady=10)
btn_scan = ttk.Button(frame_buttons, text="Scan for Files", command=scan_for_files)
btn_scan.pack(side='left', padx=5)
btn_replace = ttk.Button(frame_buttons, text="Execute Replacement", command=execute_replace)
btn_replace.pack(side='left', padx=5)

app.mainloop()
