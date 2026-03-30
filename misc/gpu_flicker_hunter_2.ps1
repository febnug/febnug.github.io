# ===============================
# GPU FLICKER HUNTER v3 (STABLE)
# ===============================

$logFile = "gpu_log.txt"
$csvFile = "gpu_log.csv"

# --- CONFIG ---
$thresholdHigh = 80
$thresholdDrop = 30
$fluctuationThreshold = 40
$minUsage = 1          # ignore noise kecil
$interval = 2

# smart detection
$flickerScore = 0
$flickerThreshold = 2
$cooldown = 5
$lastFlickerTime = Get-Date

# state tracking
$prevUsage = @{}
$freezeCount = @{}
$counter = 0

"=== GPU FLICKER HUNTER v3 START ===" | Tee-Object -FilePath $logFile
"Time,Engine,Usage" | Out-File $csvFile

Get-WmiObject Win32_VideoController | ForEach-Object {
    "GPU: $($_.Name)" | Tee-Object -FilePath $logFile -Append
    "Driver: $($_.DriverVersion)" | Tee-Object -FilePath $logFile -Append
}

"===============================" | Tee-Object -FilePath $logFile -Append

while ($true) {
    $time = Get-Date
    $timeStr = $time.ToString("HH:mm:ss.fff")

    $flickerScore = 0

    $gpuUsage = (Get-Counter '\GPU Engine(*)\Utilization Percentage').CounterSamples |
        Where-Object {$_.CookedValue -gt $minUsage} |
        Sort-Object CookedValue -Descending |
        Select-Object -First 5

    $top = $gpuUsage | Select-Object -First 1
    if ($top) {
        "DOMINANT: $($top.InstanceName)" | Tee-Object -FilePath $logFile -Append
    }

    foreach ($g in $gpuUsage) {
        $name = $g.InstanceName
        $usage = [math]::Round($g.CookedValue, 2)

        # filter engine penting saja
        if ($name -notmatch "3D|VideoDecode|VideoProcessing") {
            continue
        }

        "[$timeStr] $name : $usage%" | Tee-Object -FilePath $logFile -Append
        "$timeStr,$name,$usage" | Out-File -Append $csvFile

        if ($prevUsage.ContainsKey($name)) {
            $prev = $prevUsage[$name]

            # HIGH USAGE
            if ($usage -gt $thresholdHigh) {
                "HIGH USAGE: $name = $usage%" | Tee-Object -FilePath $logFile -Append
            }

            # SUDDEN DROP
            if ($prev -gt $thresholdHigh -and $usage -lt $thresholdDrop) {
                "SUDDEN DROP: $name ($prev -> $usage)" | Tee-Object -FilePath $logFile -Append
                $flickerScore += 2
            }

            # FLUCTUATION
            if ([math]::Abs($usage - $prev) -gt $fluctuationThreshold) {
                "FLUCTUATION: $name ($prev -> $usage)" | Tee-Object -FilePath $logFile -Append
                $flickerScore += 1
            }

            # --- SMART FREEZE DETECTION ---
            if (-not $freezeCount.ContainsKey($name)) {
                $freezeCount[$name] = 0
            }

            if ($usage -eq $prev -and $usage -gt 3) {
                $freezeCount[$name]++

                if ($freezeCount[$name] -ge 3) {
                    "FREEZE: $name stuck at $usage% for $($freezeCount[$name]) cycles" |
                        Tee-Object -FilePath $logFile -Append
                    $flickerScore += 1
                }
            } else {
                $freezeCount[$name] = 0
            }
        }

        $prevUsage[$name] = $usage
    }

    # --- DRIVER EVENT (TDR) ---
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id = 4101
        StartTime = (Get-Date).AddSeconds(-5)
    } -ErrorAction SilentlyContinue

    $tdrDetected = $false
    foreach ($e in $events) {
        "DRIVER RESET DETECTED: $($e.TimeCreated)" | Tee-Object -FilePath $logFile -Append
        $tdrDetected = $true
    }

    if ($tdrDetected) {
        $flickerScore += 3
    }

    # --- AUTO FLICKER DECISION ---
    $timeDiff = ($time - $lastFlickerTime).TotalSeconds

    if ($flickerScore -ge $flickerThreshold -and $timeDiff -gt $cooldown) {

        if ($flickerScore -ge 3) {
            $level = "HIGH"
            [console]::beep(300,600)
        } elseif ($flickerScore -eq 2) {
            $level = "MED"
            [console]::beep(800,200)
        } else {
            $level = "LOW"
        }

        "AUTO FLICKER DETECTED ($level) @ $timeStr | score=$flickerScore" |
        Tee-Object -FilePath $logFile -Append

        $lastFlickerTime = $time
    }

    # --- SUMMARY ---
    $counter++
    if ($counter -ge 15) {
        "SUMMARY @ $timeStr" | Tee-Object -FilePath $logFile -Append
        $counter = 0
    }

    Start-Sleep -Seconds $interval
}