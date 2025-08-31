# PowerShell script to set up Windows Task Scheduler for Defender Agent
# Run as Administrator

param(
    [string]$PythonPath = "python",
    [string]$AgentPath = $PSScriptRoot,
    [string]$ConfigPath = "$PSScriptRoot\agent_config.json"
)

Write-Host "Setting up Defender Agent scheduled tasks..." -ForegroundColor Cyan

# Test Python installation
try {
    $pythonVersion = & $PythonPath --version 2>&1
    Write-Host "Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found at '$PythonPath'. Please specify correct path." -ForegroundColor Red
    exit 1
}

# Test agent installation
$agentScript = Join-Path $AgentPath "defender_agent.py"
if (-not (Test-Path $agentScript)) {
    Write-Host "Agent script not found at '$agentScript'" -ForegroundColor Red
    exit 1
}

# Test configuration
if (-not (Test-Path $ConfigPath)) {
    Write-Host "Configuration not found at '$ConfigPath'" -ForegroundColor Yellow
    Write-Host "Creating from template..."
    
    $templatePath = Join-Path $AgentPath "agent_config.json.template"
    if (Test-Path $templatePath) {
        Copy-Item $templatePath $ConfigPath
        Write-Host "Created config file. Please edit with your Azure credentials." -ForegroundColor Yellow
        exit 1
    }
}

# Create scheduled tasks
Write-Host "`nCreating scheduled tasks..." -ForegroundColor Cyan

# Daily Security Check Task (8:00 AM)
$dailyAction = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument "$agentScript --config `"$ConfigPath`" --daily" `
    -WorkingDirectory $AgentPath

$dailyTrigger = New-ScheduledTaskTrigger `
    -Daily `
    -At 8:00AM

$dailySettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -MultipleInstances IgnoreNew

$dailyTask = New-ScheduledTask `
    -Action $dailyAction `
    -Trigger $dailyTrigger `
    -Settings $dailySettings `
    -Description "Daily Microsoft Defender and Entra security analysis"

# Register daily task
try {
    Register-ScheduledTask `
        -TaskName "Defender Agent - Daily Analysis" `
        -InputObject $dailyTask `
        -Force
    Write-Host "✓ Daily task created (8:00 AM)" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to create daily task: $_" -ForegroundColor Red
}

# Weekly Security Check Task (Mondays 9:00 AM)
$weeklyAction = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument "$agentScript --config `"$ConfigPath`" --weekly" `
    -WorkingDirectory $AgentPath

$weeklyTrigger = New-ScheduledTaskTrigger `
    -Weekly `
    -DaysOfWeek Monday `
    -At 9:00AM

$weeklySettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -MultipleInstances IgnoreNew

$weeklyTask = New-ScheduledTask `
    -Action $weeklyAction `
    -Trigger $weeklyTrigger `
    -Settings $weeklySettings `
    -Description "Weekly comprehensive Microsoft security analysis"

# Register weekly task
try {
    Register-ScheduledTask `
        -TaskName "Defender Agent - Weekly Analysis" `
        -InputObject $weeklyTask `
        -Force
    Write-Host "✓ Weekly task created (Mondays 9:00 AM)" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to create weekly task: $_" -ForegroundColor Red
}

# Quick Check Task (Every 4 hours during business hours)
$quickAction = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument "$agentScript --config `"$ConfigPath`" --check quick" `
    -WorkingDirectory $AgentPath

# Create triggers for business hours (8 AM, 12 PM, 4 PM)
$quickTriggers = @(
    (New-ScheduledTaskTrigger -Daily -At 8:00AM),
    (New-ScheduledTaskTrigger -Daily -At 12:00PM),
    (New-ScheduledTaskTrigger -Daily -At 4:00PM)
)

$quickSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

$quickTask = New-ScheduledTask `
    -Action $quickAction `
    -Trigger $quickTriggers `
    -Settings $quickSettings `
    -Description "Quick security check every 4 hours during business hours"

# Register quick check task
try {
    Register-ScheduledTask `
        -TaskName "Defender Agent - Quick Check" `
        -InputObject $quickTask `
        -Force
    Write-Host "✓ Quick check task created (8 AM, 12 PM, 4 PM)" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to create quick check task: $_" -ForegroundColor Red
}

# Create log cleanup task (monthly)
$cleanupScript = @"
# Clean up old reports and logs
`$reportDir = '$AgentPath\reports'
`$logFile = '$AgentPath\defender_agent.log'
`$daysToKeep = 30

# Clean old reports
Get-ChildItem `$reportDir -File | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-`$daysToKeep) } | Remove-Item -Force

# Rotate log file if too large (>100MB)
if (Test-Path `$logFile) {
    `$logSize = (Get-Item `$logFile).Length / 1MB
    if (`$logSize -gt 100) {
        `$backupName = `$logFile + '.old'
        Move-Item `$logFile `$backupName -Force
    }
}
"@

$cleanupPath = Join-Path $AgentPath "cleanup.ps1"
$cleanupScript | Out-File -FilePath $cleanupPath -Encoding UTF8

$cleanupAction = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupPath`""

$cleanupTrigger = New-ScheduledTaskTrigger `
    -Weekly `
    -DaysOfWeek Sunday `
    -At 2:00AM

$cleanupTask = New-ScheduledTask `
    -Action $cleanupAction `
    -Trigger $cleanupTrigger `
    -Settings $dailySettings `
    -Description "Clean up old Defender Agent reports and logs"

try {
    Register-ScheduledTask `
        -TaskName "Defender Agent - Cleanup" `
        -InputObject $cleanupTask `
        -Force
    Write-Host "✓ Cleanup task created (Sundays 2:00 AM)" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to create cleanup task: $_" -ForegroundColor Red
}

# Test the agent
Write-Host "`nTesting agent connection..." -ForegroundColor Cyan
$testResult = & $PythonPath $agentScript --config $ConfigPath --test 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Agent test successful!" -ForegroundColor Green
} else {
    Write-Host "✗ Agent test failed. Please check configuration." -ForegroundColor Red
    Write-Host $testResult
}

# Display summary
Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Scheduled tasks created:"
Write-Host "  • Daily Analysis: 8:00 AM"
Write-Host "  • Weekly Analysis: Mondays 9:00 AM"
Write-Host "  • Quick Checks: 8 AM, 12 PM, 4 PM"
Write-Host "  • Cleanup: Sundays 2:00 AM"

Write-Host "`nTo manage tasks:" -ForegroundColor Yellow
Write-Host "  • Open Task Scheduler (taskschd.msc)"
Write-Host "  • Look for tasks starting with 'Defender Agent'"

Write-Host "`nTo run manually:" -ForegroundColor Yellow
Write-Host "  • Daily: python $agentScript --daily"
Write-Host "  • Weekly: python $agentScript --weekly"
Write-Host "  • Test: python $agentScript --test"

Write-Host "`nReports will be saved to:" -ForegroundColor Yellow
Write-Host "  $AgentPath\reports\"