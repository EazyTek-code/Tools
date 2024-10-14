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














