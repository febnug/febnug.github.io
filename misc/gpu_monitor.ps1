$logFile = "gpu_log.txt"

# --- CONFIG ---
$thresholdHigh = 80
$thresholdDrop = 30
$fluctuationThreshold = 40

# simpan state sebelumnya
$prevUsage = @{}

Write-Output "=== GPU MONITOR + ANOMALY DETECTION ===" | Tee-Object -FilePath $logFile

Get-WmiObject Win32_VideoController | ForEach-Object {
    "GPU: $($_.Name)" | Tee-Object -FilePath $logFile -Append
    "Driver: $($_.DriverVersion)" | Tee-Object -FilePath $logFile -Append
}

"=========================" | Tee-Object -FilePath $logFile -Append

while ($true) {
    $time = Get-Date -Format "HH:mm:ss"

    $gpuUsage = (Get-Counter '\GPU Engine(*)\Utilization Percentage').CounterSamples |
        Where-Object {$_.CookedValue -gt 0} |
        Sort-Object CookedValue -Descending |
        Select-Object -First 5

    foreach ($g in $gpuUsage) {
        $name = $g.InstanceName
        $usage = [math]::Round($g.CookedValue, 2)

        $line = "[$time] $name : $usage%"
        $line | Tee-Object -FilePath $logFile -Append

        # --- ANOMALY DETECTION ---
        if ($prevUsage.ContainsKey($name)) {
            $prev = $prevUsage[$name]

            # ⚠️ HIGH USAGE
            if ($usage -gt $thresholdHigh) {
                "⚠️ HIGH USAGE: $name = $usage%" |
                Tee-Object -FilePath $logFile -Append
                [console]::beep(1000,150)
            }

            # 💀 SUDDEN DROP
            if ($prev -gt $thresholdHigh -and $usage -lt $thresholdDrop) {
                "💀 SUDDEN DROP: $name ($prev% → $usage%)" |
                Tee-Object -FilePath $logFile -Append
                [console]::beep(600,300)
            }

            # ⚡ EXTREME FLUCTUATION
            if ([math]::Abs($usage - $prev) -gt $fluctuationThreshold) {
                "⚡ EXTREME FLUCTUATION: $name ($prev% → $usage%)" |
                Tee-Object -FilePath $logFile -Append
            }
        }

        # simpan state
        $prevUsage[$name] = $usage
    }

    Start-Sleep -Seconds 2
}