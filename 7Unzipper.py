import os
import py7zr
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk  # For the progress bar

# Function to extract .7z files and update the progress bar
def extract_7z_files(directory, password, progress_bar, progress_label, total_files, window):
    extracted_files = 0
    
    for root_dir, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.7z'):
                file_path = os.path.join(root_dir, file)
                print(f"Extracting: {file_path}")
                
                try:
                    # Extract to the same folder as the archive
                    with py7zr.SevenZipFile(file_path, mode='r', password=password) as archive:
                        archive.extractall(path=root_dir)
                    print(f"Successfully extracted: {file_path}")
                    
                    # Update the progress bar and percentage label after each successful extraction
                    extracted_files += 1
                    progress = (extracted_files / total_files) * 100
                    progress_bar["value"] = progress
                    progress_label.config(text=f"{progress:.2f}%")  # Update progress label
                    window.update_idletasks()  # Ensure the GUI updates
                    
                except Exception as e:
                    # Handle any errors during extraction
                    print(f"Error extracting {file_path}: {e}")
                    messagebox.showerror("Extraction Error", f"Error extracting {file_path}: {e}")
                    return  # Stop extraction if there's an error

# Function to count total .7z files in the directory
def count_7z_files(directory):
    total_files = sum([1 for r, d, files in os.walk(directory) for file in files if file.endswith('.7z')])
    return total_files

# Function to toggle password visibility
def toggle_password():
    if show_password_var.get():
        password_entry.config(show="")  # Show password
    else:
        password_entry.config(show="*")  # Hide password

# Function to be called when the "Start Extraction" button is clicked
def start_extraction():
    directory = directory_entry.get()
    password = password_entry.get()

    if not directory or not password:
        messagebox.showwarning("Input Error", "Please provide both a directory and a password.")
        return

    total_files = count_7z_files(directory)
    
    if total_files == 0:
        messagebox.showwarning("No Files Found", "No .7z files were found in the selected directory.")
        return
    
    # Reset the progress bar and show it
    progress_bar["value"] = 0
    progress_bar.pack(pady=10)
    progress_label.config(text="0%")  # Reset progress percentage to 0%

    # Extract files and update progress bar
    extract_7z_files(directory, password, progress_bar, progress_label, total_files, root)  # Pass the Tk window here
    
    messagebox.showinfo("Success", "Extraction completed successfully.")

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
root.title("7Unzipper")

# Set the window size
root.geometry("400x500")

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
show_password_check = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password)
show_password_check.pack(pady=5)

# Create a progress bar (hidden initially)
progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_label = tk.Label(root, text="0%")  # Progress percentage label

# Create a button to start extraction (with larger font and padding)
extract_button = tk.Button(root, text="Start Extraction", command=start_extraction, font=("Arial", 14), padx=20, pady=10)
extract_button.pack(pady=20)

# Add progress bar and label below the extraction button
progress_bar.pack(pady=10)
progress_label.pack()

# Create the exit button with more size adjustments
exit_button = tk.Button(root, text="EXIT", command=exit_application, font=("Arial", 16, "bold"), padx=40, pady=20)  # More padding and bold font
exit_button.pack(pady=30)

# Run the main loop
root.mainloop()
