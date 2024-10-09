Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Configuration file to store last used paths
$configFilePath = "$([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'YaraProcessScanner.config'))"

# Load last used paths
$lastPaths = @{
    YaraBinaryPath = ""
    YaraRulePath = ""
}
if (Test-Path $configFilePath) {
    $lastPaths = Get-Content -Path $configFilePath | ConvertFrom-Json
}

# Get the path to the user's Desktop
$desktopPath = [System.Environment]::GetFolderPath('Desktop')

# Function to log activity
function Log-Activity {
    param (
        [string]$message
    )
    $activityLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $message`r`n")
}

# Function to generate a stylish HTML YARA scan report
function Generate-YaraReport {
    param (
        [string]$outputFileName,
        [array]$matchesList
    )

    # Start HTML report content with inline CSS
    $reportContent = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>YARA Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #121212; color: #e0e0e0; margin: 20px; }
        h1 { color: #ffa500; text-align: center; }
        .match-container { background-color: #1e1e1e; margin-bottom: 20px; padding: 10px; border: 1px solid #444; border-radius: 5px; }
        .match-header { font-size: 1.2em; color: #ffa500; margin-bottom: 5px; }
        .match-details { margin-left: 20px; }
        .detection-strings { margin-left: 40px; margin-top: 5px; color: #b0b0b0; font-family: monospace; }
    </style>
</head>
<body>
    <h1>YARA Scan Report</h1>
"@

    foreach ($match in $matchesList) {
        $reportContent += @"
        <div class='match-container'>
            <div class='match-header'>Process: $($match.ProcessName) (PID: $($match.PID))</div>
            <div class='match-details'>Path: $($match.ProcessPath)</div>
            <div class='match-details'>Rule: $($match.RuleName)</div>
            <div class='detection-strings'>
"@

        # Format detection strings for new line appearance
        $detectionStrings = $match.Detections -split "`n"
        foreach ($string in $detectionStrings) {
            $reportContent += "                $string<br>`n"
        }

        $reportContent += @"
            </div>
        </div>
"@
    }

    $reportContent += "</body></html>"

    # Write to file
    $fullFilePath = [System.IO.Path]::Combine($desktopPath, $outputFileName)
    Set-Content -Path $fullFilePath -Value $reportContent
    Log-Activity "YARA scan report generated: $fullFilePath"
}

# Function to terminate a process by PID
function Terminate-Process {
    param (
        [int]$processId,
        [string]$processName
    )
    try {
        Stop-Process -Id $processId -Force
        Log-Activity "Successfully terminated process $processName (PID: $processId)"
    } catch {
        Log-Activity "Error terminating process $processName (PID: $processId): $_"
    }
}

# Function to scan the user-selected binary process
function Scan-UserSelectedProcess {
    Log-Activity "Starting YARA scan for the selected binary..."
    Save-LastPaths

    $yaraBinaryPath = $yaraBinaryTextbox.Text
    $yaraRulePath = $yaraRuleTextbox.Text
    $processPath = $processPathTextbox.Text
    $matchesList = @()
    $timeStamp = (Get-Date -Format "yyyyMMddHHmmss")
    $outputFileName = "YaraScanReport_$timeStamp.html"

    if (-not (Test-Path $yaraBinaryPath)) {
        Log-Activity "YARA binary not found: $yaraBinaryPath"
        return
    }

    if (-not (Test-Path $yaraRulePath)) {
        Log-Activity "YARA rule file not found: $yaraRulePath"
        return
    }

    if (-not (Test-Path $processPath)) {
        Log-Activity "Process binary not found: $processPath"
        return
    }

    # Launch the selected process
    try {
        $process = Start-Process -FilePath $processPath -PassThru
        $processId = $process.Id
        $processName = $process.ProcessName

        Log-Activity "Launching selected binary: $processPath"
        Log-Activity "Executing YARA command on process $processName (PID: $processId)"

        $result = & "$yaraBinaryPath" -s $yaraRulePath $processId
        if ($result -and $result -notmatch "no matches found") {
            $matchesList += [pscustomobject]@{
                ProcessName = $processName
                PID = $processId
                ProcessPath = $processPath
                RuleName = "YARA Rule"
                Detections = $result
            }
            Log-Activity "YARA detected matches in process $processName (PID: $processId)"
        } else {
            Log-Activity "No matches found in process $processName (PID: $processId)"
        }

        if ($matchesList.Count -gt 0) {
            Generate-YaraReport -outputFileName $outputFileName -matchesList $matchesList
        } else {
            Log-Activity "No matches found."
        }

        # Terminate the process after scanning
        Terminate-Process -processId $processId -processName $processName
    } catch {
        Log-Activity "Error starting or finding the selected process: $_"
    }

    Log-Activity "YARA scan for the selected binary completed."
}

# Function to scan all running processes
function Scan-AllProcesses {
    Log-Activity "Starting YARA scan for all processes..."
    Save-LastPaths

    $yaraBinaryPath = $yaraBinaryTextbox.Text
    $yaraRulePath = $yaraRuleTextbox.Text
    $matchesList = @()
    $timeStamp = (Get-Date -Format "yyyyMMddHHmmss")
    $outputFileName = "YaraScanReport_$timeStamp.html"

    if (-not (Test-Path $yaraBinaryPath)) {
        Log-Activity "YARA binary not found: $yaraBinaryPath"
        return
    }

    if (-not (Test-Path $yaraRulePath)) {
        Log-Activity "YARA rule file not found: $yaraRulePath"
        return
    }

    $processes = Get-Process
    $progressBar.Maximum = $processes.Count
    $progressBar.Value = 0

    foreach ($process in $processes) {
        $processId = $process.Id
        $processName = $process.Name
        $processPath = "N/A"
        try {
            $processPath = $process.Path
        } catch {
            Log-Activity "Could not retrieve path for process $processName (PID: $processId)"
        }

        $yaraCommand = "$yaraBinaryPath -s $yaraRulePath $processId"
        Log-Activity "Executing YARA command on process $processName (PID: $processId)"

        try {
            $result = & "$yaraBinaryPath" -s $yaraRulePath $processId
            if ($result -and $result -notmatch "no matches found") {
                $matchesList += [pscustomobject]@{
                    ProcessName = $processName
                    PID = $processId
                    ProcessPath = $processPath
                    RuleName = "YARA Rule"
                    Detections = $result
                }
                Log-Activity "YARA detected matches in process $processName (PID: $processId)"
            } else {
                Log-Activity "No matches found in process $processName (PID: $processId)"
            }
        } catch {
            Log-Activity "Error scanning process ${processName}: $_"
        }

        $progressBar.Value += 1
    }

    if ($matchesList.Count -gt 0) {
        Generate-YaraReport -outputFileName $outputFileName -matchesList $matchesList
    } else {
        Log-Activity "No matches found."
    }

    Log-Activity "YARA scan for all processes completed."
}

# Define form and its properties
$form = New-Object System.Windows.Forms.Form
$form.Text = "YARA Process Scanner"
$form.Size = New-Object System.Drawing.Size(600, 650)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# Define fonts and colors for a modern look
$font = New-Object System.Drawing.Font("Segoe UI", 10)
$backgroundColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
$foregroundColor = [System.Drawing.Color]::FromArgb(224, 224, 224)

$form.BackColor = $backgroundColor
$form.ForeColor = $foregroundColor

# Define labels and textboxes for YARA Binary
$yaraBinaryLabel = New-Object System.Windows.Forms.Label
$yaraBinaryLabel.Text = "YARA Binary Path:"
$yaraBinaryLabel.Location = New-Object System.Drawing.Point(20, 20)
$yaraBinaryLabel.ForeColor = $foregroundColor
$yaraBinaryLabel.AutoSize = $true
$form.Controls.Add($yaraBinaryLabel)

$yaraBinaryTextbox = New-Object System.Windows.Forms.TextBox
$yaraBinaryTextbox.Size = New-Object System.Drawing.Size(400, 30)
$yaraBinaryTextbox.Location = New-Object System.Drawing.Point(20, 50)
$yaraBinaryTextbox.Text = $lastPaths.YaraBinaryPath
$yaraBinaryTextbox.Font = $font
$form.Controls.Add($yaraBinaryTextbox)

# Browse button for YARA binary
$browseYaraBinaryButton = New-Object System.Windows.Forms.Button
$browseYaraBinaryButton.Text = "Browse"
$browseYaraBinaryButton.Location = New-Object System.Drawing.Point(430, 50)
$browseYaraBinaryButton.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($browseYaraBinaryButton)

# Define labels and textboxes for YARA Rule
$yaraRuleLabel = New-Object System.Windows.Forms.Label
$yaraRuleLabel.Text = "YARA Rule File:"
$yaraRuleLabel.Location = New-Object System.Drawing.Point(20, 100)
$yaraRuleLabel.ForeColor = $foregroundColor
$yaraRuleLabel.AutoSize = $true
$form.Controls.Add($yaraRuleLabel)

$yaraRuleTextbox = New-Object System.Windows.Forms.TextBox
$yaraRuleTextbox.Size = New-Object System.Drawing.Size(400, 30)
$yaraRuleTextbox.Location = New-Object System.Drawing.Point(20, 130)
$yaraRuleTextbox.Text = $lastPaths.YaraRulePath
$yaraRuleTextbox.Font = $font
$form.Controls.Add($yaraRuleTextbox)

# Browse button for YARA rule file
$browseYaraRuleButton = New-Object System.Windows.Forms.Button
$browseYaraRuleButton.Text = "Browse"
$browseYaraRuleButton.Location = New-Object System.Drawing.Point(430, 130)
$browseYaraRuleButton.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($browseYaraRuleButton)

# Define labels and textboxes for process selection
$processPathLabel = New-Object System.Windows.Forms.Label
$processPathLabel.Text = "Process Binary Path:"
$processPathLabel.Location = New-Object System.Drawing.Point(20, 180)
$processPathLabel.ForeColor = $foregroundColor
$processPathLabel.AutoSize = $true
$form.Controls.Add($processPathLabel)

$processPathTextbox = New-Object System.Windows.Forms.TextBox
$processPathTextbox.Size = New-Object System.Drawing.Size(400, 30)
$processPathTextbox.Location = New-Object System.Drawing.Point(20, 210)
$processPathTextbox.Font = $font
$form.Controls.Add($processPathTextbox)

# Browse button for Process binary
$browseProcessPathButton = New-Object System.Windows.Forms.Button
$browseProcessPathButton.Text = "Browse"
$browseProcessPathButton.Location = New-Object System.Drawing.Point(430, 210)
$browseProcessPathButton.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($browseProcessPathButton)

# Checkbox to scan all processes
$scanAllProcessesCheckbox = New-Object System.Windows.Forms.CheckBox
$scanAllProcessesCheckbox.Text = "Scan All Running Processes"
$scanAllProcessesCheckbox.Location = New-Object System.Drawing.Point(20, 250)
$scanAllProcessesCheckbox.AutoSize = $true
$scanAllProcessesCheckbox.ForeColor = $foregroundColor
$form.Controls.Add($scanAllProcessesCheckbox)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(500, 20)
$progressBar.Location = New-Object System.Drawing.Point(20, 280)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$form.Controls.Add($progressBar)

# Activity log text box
$activityLog = New-Object System.Windows.Forms.TextBox
$activityLog.Multiline = $true
$activityLog.ScrollBars = "Vertical"
$activityLog.ReadOnly = $true
$activityLog.Size = New-Object System.Drawing.Size(500, 150)
$activityLog.Location = New-Object System.Drawing.Point(20, 310)
$form.Controls.Add($activityLog)

# Scan button
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Run YARA Scan"
$scanButton.Location = New-Object System.Drawing.Point(150, 500)
$scanButton.Size = New-Object System.Drawing.Size(150, 40)
$form.Controls.Add($scanButton)

# Exit button
$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Text = "Exit"
$exitButton.Location = New-Object System.Drawing.Point(320, 500)
$exitButton.Size = New-Object System.Drawing.Size(100, 40)
$form.Controls.Add($exitButton)

# Event handlers for browse buttons
$browseYaraBinaryButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Executable Files (*.exe)|*.exe"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $yaraBinaryTextbox.Text = $openFileDialog.FileName
    }
})

$browseYaraRuleButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "YARA Files (*.yara;*.yar)|*.yara;*.yar"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $yaraRuleTextbox.Text = $openFileDialog.FileName
    }
})

$browseProcessPathButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Executable Files (*.exe)|*.exe"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $processPathTextbox.Text = $openFileDialog.FileName
    }
})

# Save the last used paths to a configuration file
function Save-LastPaths {
    $lastPaths.YaraBinaryPath = $yaraBinaryTextbox.Text
    $lastPaths.YaraRulePath = $yaraRuleTextbox.Text
    $lastPaths | ConvertTo-Json | Set-Content -Path $configFilePath
}

# Scan button logic (includes option for scanning all processes)
$scanButton.Add_Click({
    if ($scanAllProcessesCheckbox.Checked) {
        Scan-AllProcesses
    } else {
        Scan-UserSelectedProcess
    }
})

# Exit button logic
$exitButton.Add_Click({
    Log-Activity "Exiting program."
    $form.Close()
})

$form.ShowDialog()
