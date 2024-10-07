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

# Function to terminate processes based on PID list
function Terminate-Processes {
    param (
        [array]$processIds
    )

    foreach ($processId in $processIds) {
        try {
            Stop-Process -Id $processId -Force
            Log-Activity "Terminated process with PID: $processId"
        } catch {
            Log-Activity "Error terminating process with PID: $processId - $_"
        }
    }
}

# Define form and its properties
$form = New-Object System.Windows.Forms.Form
$form.Text = "YARA Process Scanner"
$form.Size = New-Object System.Drawing.Size(600, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# Define fonts and colors for a modern look
$font = New-Object System.Drawing.Font("Segoe UI", 10)
$backgroundColor = [System.Drawing.Color]::FromArgb(18, 18, 18)  # Dark background
$foregroundColor = [System.Drawing.Color]::FromArgb(224, 224, 224)  # Light text

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

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(500, 20)
$progressBar.Location = New-Object System.Drawing.Point(20, 260)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$form.Controls.Add($progressBar)

# Activity log text box
$activityLog = New-Object System.Windows.Forms.TextBox
$activityLog.Multiline = $true
$activityLog.ScrollBars = "Vertical"
$activityLog.ReadOnly = $true
$activityLog.Size = New-Object System.Drawing.Size(500, 150)
$activityLog.Location = New-Object System.Drawing.Point(20, 290)
$form.Controls.Add($activityLog)

# Scan button
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Run YARA Scan"
$scanButton.Location = New-Object System.Drawing.Point(150, 460)
$scanButton.Size = New-Object System.Drawing.Size(150, 40)
$form.Controls.Add($scanButton)

# Exit button
$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Text = "Exit"
$exitButton.Location = New-Object System.Drawing.Point(320, 460)
$exitButton.Size = New-Object System.Drawing.Size(100, 40)
$form.Controls.Add($exitButton)

# Event handler for browse buttons
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

# Scan button logic
$scanButton.Add_Click({
    Log-Activity "Starting YARA scan..."
    Save-LastPaths

    $yaraBinaryPath = $yaraBinaryTextbox.Text
    $yaraRulePath = $yaraRuleTextbox.Text
    $matchesList = @()
    $timeStamp = (Get-Date -Format "yyyyMMddHHmmss")
    $outputFileName = "YaraScanReport_$timeStamp.html"
    $selectedProcess = $null
    $selectedProcessId = $null
    $selectedProcessName = $null
    $initialProcesses = Get-Process

    $binaryPath = $processPathTextbox.Text
    if (-not (Test-Path $binaryPath)) {
        Log-Activity "Selected binary not found: $binaryPath"
        return
    }

    try {
        Log-Activity "Launching selected binary: $binaryPath"
        $selectedProcess = Start-Process -FilePath $binaryPath -PassThru
        Start-Sleep -Seconds 5

        $finalProcesses = Get-Process
        $newProcesses = $finalProcesses | Where-Object { $_.Id -notin $initialProcesses.Id }
        $newProcessIds = $newProcesses | Select-Object -ExpandProperty Id

        # Run YARA scan on new processes
        foreach ($processId in $newProcessIds) {
            $process = Get-Process -Id $processId
            $processName = $process.Name
            Log-Activity "Executing YARA command on process $processName (PID: $processId)"
            try {
                $result = & "$yaraBinaryPath" -s $yaraRulePath $processId
                if ($result -and $result -notmatch "no matches found") {
                    $matchesList += [pscustomobject]@{
                        ProcessName = $processName
                        PID = $processId
                        ProcessPath = $processPathTextbox.Text
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
        }

        if ($matchesList.Count -gt 0) {
            Generate-YaraReport -outputFileName $outputFileName -matchesList $matchesList
        } else {
            Log-Activity "No matches found."
        }

        # Terminate all new processes
        Terminate-Processes -processIds $newProcessIds
    } catch {
        Log-Activity "Error launching or scanning the process: $_"
    }

    Log-Activity "YARA scan completed."
})

# Exit button logic
$exitButton.Add_Click({
    Log-Activity "Exiting program."
    $form.Close()
})

$form.ShowDialog()
