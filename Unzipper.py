import os
import time
import patoolib
import py7zr
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread

# Function to extract a single archive file based on its type
def extract_single_file(file_path, password, root_dir):
    try:
        start_time = time.time()
        if file_path.endswith('.7z'):
            # Use py7zr for 7z files
            with py7zr.SevenZipFile(file_path, mode='r', password=password) as archive:
                archive.extractall(path=root_dir)
        else:
            # Use patool for other archive types
            patoolib.extract_archive(file_path, outdir=root_dir)
        elapsed_time = time.time() - start_time
        return file_path, True, elapsed_time
    except Exception as e:
        print(f"Error extracting {file_path}: {e}")
        return file_path, False, 0

# Function to manage multithreaded extraction of files
def extract_7z_files_multithreaded(files_list, password, progress_bar, progress_label, time_label, window):
    total_files = len(files_list)
    extracted_files = 0
    total_time_spent = 0

    def update_progress(elapsed_time):
        nonlocal extracted_files, total_time_spent
        extracted_files += 1
        total_time_spent += elapsed_time
        progress = (extracted_files / total_files) * 100
        progress_bar["value"] = progress
        progress_label.config(text=f"{progress:.2f}%")

        if extracted_files > 0:
            avg_time_per_file = total_time_spent / extracted_files
            remaining_files = total_files - extracted_files
            estimated_time_remaining = avg_time_per_file * remaining_files

            # Convert estimated time remaining to minutes and seconds
            mins, secs = divmod(estimated_time_remaining, 60)
            time_label.config(text=f"Estimated Time Remaining: {int(mins)} min {int(secs)} sec")

        window.after(100, window.update_idletasks)

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(extract_single_file, file_path, password, root_dir): file_path for file_path, root_dir in files_list}

        for future in as_completed(futures):
            file_path, success, elapsed_time = future.result()
            if success:
                window.after(0, update_progress, elapsed_time)  # Update progress in the main thread

# Function to gather all archive files from the selected directory
def gather_archive_files(directory):
    supported_extensions = ['.7z', '.zip', '.rar', '.tar', '.gz', '.bz2']
    files_list = []
    for root_dir, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in supported_extensions):
                files_list.append((os.path.join(root_dir, file), root_dir))
    return files_list

# Function to be called when the "Start Extraction" button is clicked
def start_extraction():
    directory = directory_entry.get()
    password = password_entry.get()

    if not directory or not password:
        messagebox.showwarning("Input Error", "Please provide both a directory and a password.")
        return

    files_list = gather_archive_files(directory)

    if len(files_list) == 0:
        messagebox.showwarning("No Files Found", "No archive files were found in the selected directory.")
        return

    # Reset the progress bar and show it
    progress_bar["value"] = 0
    progress_bar.pack(pady=10)
    progress_label.config(text="0%")  # Reset progress percentage to 0%
    time_label.config(text="Estimated Time Remaining: Calculating...")

    # Run extraction in a separate thread to avoid freezing the GUI
    extraction_thread = Thread(target=extract_7z_files_multithreaded, args=(files_list, password, progress_bar, progress_label, time_label, root))
    extraction_thread.start()

# Function to browse for a directory
def browse_directory():
    directory = filedialog.askdirectory()
    if directory:
        directory_entry.delete(0, tk.END)  # Clear the current text
        directory_entry.insert(0, directory)  # Insert the selected directory

# Function to exit the application
def exit_application():
    root.quit()

# Create the main window
root = tk.Tk()
root.title("Archive Extractor")

# Set the window size
root.geometry("400x550")

# Create a label and text entry for the directory path
directory_label = tk.Label(root, text="Directory Path:")
directory_label.pack(pady=5)

directory_entry = tk.Entry(root, width=50)
directory_entry.pack(pady=5)

# Create a browse button for the directory path
browse_button = tk.Button(root, text="Browse", command=browse_directory)
browse_button.pack(pady=5)

# Create a label and text entry for the password
password_label = tk.Label(root, text="Password:")
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="*", width=50)  # Password hidden by default
password_entry.pack(pady=5)

# Create a checkbox to show/hide the password
show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=lambda: password_entry.config(show="" if show_password_var.get() else "*"))
show_password_check.pack(pady=5)

# Create a progress bar (hidden initially)
progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_label = tk.Label(root, text="0%")  # Progress percentage label
time_label = tk.Label(root, text="Estimated Time Remaining: Calculating...")  # Time remaining label

# Create a button to start extraction (with larger font and padding)
extract_button = tk.Button(root, text="Start Extraction", command=start_extraction, font=("Arial", 14), padx=20, pady=10)
extract_button.pack(pady=20)

# Add progress bar and label below the extraction button
progress_bar.pack(pady=10)
progress_label.pack()
time_label.pack(pady=10)

# Create the exit button with more size adjustments
exit_button = tk.Button(root, text="EXIT", command=exit_application, font=("Arial", 16, "bold"), padx=50, pady=20)
exit_button.pack(pady=30)

# Run the main loop
root.mainloop()
