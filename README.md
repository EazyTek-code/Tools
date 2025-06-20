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


---
---



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


---
---


# YaraRunner.exe 🧩🔍

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/) ![License](https://img.shields.io/badge/License-GPL-green.svg) ![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-lightgreen.svg)

**YaraRunner** is an open-source utility designed to run YARA rule scans on directories, generating detailed reports with matched detections. The tool helps system administrators and cybersecurity professionals easily scan for malware and other threats.

---

## Features ✨

- 📁 **File and Directory Scanning**: Runs YARA rule files against specified files or directories, identifying matches.
- 🧩 **Interactive HTML Reports**: Generates an interactive HTML report with filtering and search functionality for matched rules.
- 📝 **Rule Matching Summary**: Displays a clear summary of rule matches, showing the total number of files scanned and matched.
- 🖥️ **Automatic Report Generation**: Automatically generates both HTML and text-based reports upon scan completion.
- 💾 **User-Configurable Settings**: Allows users to specify custom YARA rule files and target directories.
- 🎛️ **User-Friendly GUI**: Intuitive graphical interface built with `tkinter`, making it easy to perform scans and view results.
- 🌐 **Open Source**: Available under the GPL License, encouraging community contributions and collaboration.

---

## Getting Started 🚀

### Prerequisites
- [Python 3.x](https://www.python.org/downloads/)
- [YARA](https://virustotal.github.io/yara/)

---
---



# 🛡️ PSYara

[![PowerShell](https://img.shields.io/badge/PowerShell-5.0+-blue.svg)](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
![License](https://img.shields.io/badge/License-GPL-green.svg)
[![YARA](https://img.shields.io/badge/YARA-4.0+-orange.svg)](https://github.com/VirusTotal/yara/releases)

## 🔍 Overview

**PSYara** is a Windows-based utility with a GUI that allows you to scan running processes or specific binaries in memory using YARA rules. The tool generates a filterable HTML report for rule detections, with details on the matching rules and detection strings.

## ✨ Features

- **Scan all running processes** for YARA rule matches.
- **Select a binary** to scan in memory.


## 📋 Prerequisites

- **PowerShell 5.0+** (comes pre-installed on most Windows systems).
- **YARA Binary**: Download the latest `yara64.exe` from [YARA's official GitHub](https://github.com/VirusTotal/yara/releases).
- **YARA Rule File**: A `.yar` or `.yara` file containing the detection rules.

---
---

# YaraMerge ![logo](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-GPL-green.svg) ![OpenSource](https://img.shields.io/badge/OpenSource-💚-green.svg)

**YaraMerge** is an open-source utility designed to parse folder subdirectories, find all YARA rule files, and merge them into one master YARA file with proper formatting. This tool ensures that all YARA rules are neatly combined, with user-friendly options through an intuitive GUI. It is an essential tool for anyone working with large YARA rule sets, offering flexibility, ease of use, and efficient rule management.

## Features ✨

- 🗂 **Directory Parsing**: Recursively scans subdirectories to identify and collect all YARA rule files (`.yara`/`.yar`).
- 🔄 **Rule Deduplication**: Automatically checks for and skips duplicate YARA rule names during the merging process.
- 📝 **Custom Rule Formatting**: Ensures three blank lines between each merged YARA rule for readability.
- 🖥️ **User-Friendly GUI**: A modern and intuitive graphical interface, making it easy for users to select directories and merge files.
- 💾 **Automatic Output**: Saves the merged YARA file to a specified location with a custom name.
- 🚀 **Cross-Platform**: Works on both Windows and Linux environments.

---
---

# FindReplaceTool 📝🔍

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Status](https://img.shields.io/badge/Status-Open%20Source-brightgreen.svg)

**FindReplaceTool** is an open-source GUI-based tool designed to help users search and replace text in files across directories and subdirectories. With a user-friendly interface, it enables users to locate files containing specific text, review and select files for editing, and apply bulk replacements with ease.



## Features ✨

- 📂 **Directory Scanning**: Recursively scans the specified directory and subdirectories for files containing a specified search string.
- 🔄 **String Replacement**: Allows replacement of a search string with a specified replacement string in selected files.
- 📝 **File Extension Filtering**: Optionally filter the files to be scanned by their extension (e.g., `.txt`, `.log`).
- ✅ **Selective File Modification**: Presents a list of files containing the search string, allowing users to select specific files to modify.
- 🖥️ **User-Friendly Interface**: Modern, intuitive graphical interface built with `tkinter` for ease of use.
- 📜 **Open Source**: Available under the MIT License, encouraging community contributions and collaboration.

---
---

# Yara Scanner 🕵️‍♂️

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Status](https://img.shields.io/badge/Status-Open%20Source-brightgreen.svg)

Yara Scanner is an open-source utility designed for Windows to scan files, live memory, targeted processes, or lanuch and suspend processes in order to scan memory space with YARA rules. It provides a user-friendly interface to select YARA rule files, configure scan parameters, exclude specific processes or paths, and generate detailed HTML reports to help security professionals and system administrators monitor and analyze system states.

## Features ✨

- 🗂️ **File System Scanning**: Scans entire drives or specific directories for files matching YARA rules.
- 💾 **Live Memory Scanning**: Scans the memory of all running processes (excluding user-specified processes).
- 🎯 **Targeted Process Scanning**: Launches and scans a specific executable or DLL, with the option to suspend it after a delay.
- ⏳ **Process Suspension**: Launches and suspends a specific executable or DLL immediately or after a delay.
- 🚫 **Exclusion Support**: Allows exclusion of specific processes by name or PID, and specific files or directories.
- ⚡ **Multithreaded Scanning**: Utilizes multiple threads based on CPU count for efficient file system scanning.
- 📊 **HTML Report Generation**: Creates an interactive HTML report with detailed scan results, including matched rules and strings.
- 🎨 **User-Friendly GUI**: Intuitive graphical interface built with `customtkinter`.
- 🌍 **Open Source**: Available under the GPL License, encouraging community contributions and collaboration.

---
---















