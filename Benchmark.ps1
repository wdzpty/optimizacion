# Benchmark.ps1
Clear-Host
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logPath = "$PSScriptRoot\benchmark_result_$timestamp.txt"

function Get-CPUUsage {
    $cpu = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average
    return [math]::Round($cpu.Average, 2)
}

function Get-RAMUsage {
    $os = Get-CimInstance Win32_OperatingSystem
    $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $used = [math]::Round($total - $free, 2)
    $percent = [math]::Round(($used / $total) * 100, 2)
    return "$used GB / $total GB ($percent%)"
}

function Get-Ping {
    $ping = Test-Connection google.com -Count 5 -Quiet:$false | Measure-Object -Property ResponseTime -Average
    return "$([math]::Round($ping.Average, 2)) ms"
}

function Get-BootTime {
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    return "$([math]::Round($uptime.TotalMinutes, 2)) minutos desde el último arranque"
}

# --- Registro ---
Add-Content $logPath "===== BENCHMARK DE RENDIMIENTO ====="
Add-Content $logPath "Fecha: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
Add-Content $logPath "`n--- SISTEMA ---"
Add-Content $logPath "Tiempo desde el arranque: $(Get-BootTime)"

Add-Content $logPath "`n--- CPU ---"
Add-Content $logPath "Uso de CPU actual: $(Get-CPUUsage)%"

Add-Content $logPath "`n--- RAM ---"
Add-Content $logPath "Uso de RAM actual: $(Get-RAMUsage)"

Add-Content $logPath "`n--- RED ---"
Add-Content $logPath "Latencia promedio a google.com: $(Get-Ping)"

Add-Content $logPath "`n===== FIN DEL REPORTE =====`n"

# Mostrar ruta
Write-Host "`nBenchmark completado. Resultados guardados en:`n$logPath" -ForegroundColor Green
Pause
