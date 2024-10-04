# SystemMapper.exe 🖥️🔍

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-GPL-green.svg)
![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)

SystemMapper is an open-source utility designed to map the Windows file system and registry, save the results to a database, and compare different system states. It generates detailed HTML reports to help system administrators and cybersecurity professionals monitor changes and detect unauthorized modifications.

## Features ✨
- 📁 **File System Mapping**: Scans and maps the file system to capture file paths, sizes, and modification times.
- 🛠️ **Registry Mapping**: Maps Windows registry across multiple hives to track system configurations and changes.
- 💾 **Automatic Database Saving**: Saves mapping results to a database file with a timestamp.
- 📊 **System State Comparison**: Compares database files to identify added, removed, and modified files or registry keys.
- 📑 **HTML Report Generation**: Creates an interactive HTML report with filtering options for files or processes.
- 🖼️ **User-Friendly GUI**: Intuitive graphical interface built with `tkinter`.
- 🌐 **Open Source**: Available under the GPL License, encouraging community contributions and collaboration.






# Unzipper.exe 🚀

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-GPL-green.svg)
![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)

Unzipper is an open-source tool designed to decompress various archive formats such as `.7z`, `.zip`, `.rar`, `.tar`, `.gz`, `.bz2`, and more. The tool provides a simple and intuitive GUI to select files, input passwords (if needed), and extract files efficiently. It also features multithreading to speed up the extraction process and displays an estimated time for completion.

## Features ✨
- 🗂 **Support for Multiple Archive Formats**: Decompresses `.7z`, `.zip`, `.rar`, `.tar`, `.gz`, `.bz2`, and other archive formats.
- 🔒 **Password-Protected Archives**: Supports extraction of password-protected archives.
- ⚡ **Multithreading**: Utilizes multithreading to speed up the extraction process.
- ⏱ **Estimated Time Remaining**: Displays the estimated time to complete the extraction process.
- 💻 **GUI**: User-friendly graphical interface using `tkinter`.
- 🌐 **Open Source**: Available under the GPL License, encouraging community contributions and collaboration.






# YaraRunner 🛡️🔍

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-GPL-green.svg)
![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)

YaraRunner is an open-source utility designed to scan files, directories, and running processes for potential malware using YARA rules. It generates detailed HTML reports, making it easier for cybersecurity professionals to identify and analyze threats in the system.

## Features ✨

- 🗂️ **File and Directory Scanning**: Scans files and directories using YARA rules to identify potential malware and threats.
- 📋 **Comprehensive Reports**: Generates a detailed HTML report of all detections, with search and filtering options for easy analysis.
- 🔧 **Customizable YARA Binary Path**: Allows users to specify the path to their YARA binary, offering flexibility and ease of configuration.
- 🖼️ **User-Friendly GUI**: Provides a modern and intuitive graphical interface built with `tkinter`.
- 🌐 **Open Source**: Available under the GPL License, encouraging community contributions and collaboration.

## Getting Started 🚀

### Prerequisites

- **Python**: Ensure Python 3.x is installed on your system.
- **YARA Binary**: Download the YARA binary from the [official YARA GitHub repository](https://github.com/VirusTotal/yara).


### GUI Overview

1. **YARA Binary Path**: Select the path to your YARA binary using the 'Browse' button.
2. **YARA Rule File**: Choose the YARA rule file for scanning.
3. **Target Directory**: Specify the directory or files you want to scan.
4. **Run Scan**: Click "Run YARA Scan" to start scanning the selected files or directories.
5. **View Report**: After the scan completes, view the generated HTML report with the scan results.

### Example

1. Open the tool and set the YARA binary path, rule file, and target directory.
2. Click "Run YARA Scan" to perform the file or directory scan.
3. Review the generated HTML report for detailed detection results.



# 🛡️ YARA Process Scanner

[![PowerShell](https://img.shields.io/badge/PowerShell-5.0+-blue.svg)](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
![License](https://img.shields.io/badge/License-GPL-green.svg)
[![YARA](https://img.shields.io/badge/YARA-4.0+-orange.svg)](https://github.com/VirusTotal/yara/releases)

## 🔍 Overview

**YARA Process Scanner** is a Windows-based utility with a GUI that allows you to scan running processes or specific binaries in memory using YARA rules. The tool generates a filterable HTML report for rule detections, with details on the matching rules and detection strings.

## ✨ Features

- **Scan all running processes** for YARA rule matches.
- **Select a binary** to scan in memory.


## 📋 Prerequisites

- **PowerShell 5.0+** (comes pre-installed on most Windows systems).
- **YARA Binary**: Download the latest `yara64.exe` from [YARA's official GitHub](https://github.com/VirusTotal/yara/releases).
- **YARA Rule File**: A `.yar` or `.yara` file containing the detection rules.









