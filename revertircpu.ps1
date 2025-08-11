# Revertir cambios de Optimización extrema de CPU
# Ejecutar como Administrador

Write-Host "Restaurando configuración de CPU y Windows..." -ForegroundColor Cyan

# 1. Restaurar plan de energía por defecto (Balanceado)
Write-Host "Restaurando plan de energía 'Equilibrado'..." -ForegroundColor Yellow
powercfg -setactive SCHEME_BALANCED

# 2. Reactivar servicios que fueron desactivados
$Servicios = @(
    "DiagTrack",   # Telemetría
    "SysMain",     # Superfetch
    "WSearch",     # Indexación
    "Fax",
    "Spooler",     # Impresoras
    "WerSvc",      # Informe de errores
    "RetailDemo"
)
foreach ($serv in $Servicios) {
    Write-Host "Reactivando servicio: $serv" -ForegroundColor Green
    Set-Service -Name $serv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $serv -ErrorAction SilentlyContinue
}

# 3. Restaurar prioridad por defecto de procesos de juegos
$Juegos = "FiveM_GTAProcess.exe","FortniteClient-Win64-Shipping.exe","VALORANT-Win64-Shipping.exe"
foreach ($juego in $Juegos) {
    $proc = Get-Process | Where-Object { $_.ProcessName -like "*$($juego.Split('.')[0])*" }
    if ($proc) {
        Write-Host "Restaurando prioridad normal para $($proc.ProcessName)" -ForegroundColor Yellow
        $proc.PriorityClass = "Normal"
    }
}

# 4. Restaurar afinidad de CPU por defecto (Windows decide)
foreach ($juego in $Juegos) {
    $proc = Get-Process | Where-Object { $_.ProcessName -like "*$($juego.Split('.')[0])*" }
    if ($proc) {
        $mask = 0  # 0 = Afinidad por defecto gestionada por Windows
        $proc.ProcessorAffinity = [IntPtr]::Zero
    }
}

# 5. Revertir ajustes de bcdedit
Write-Host "Restaurando configuración de latencia..." -ForegroundColor Yellow
bcdedit /deletevalue disabledynamictick
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue tscsyncpolicy

Write-Host ""
Write-Host "Restauración completada. Reinicia el PC para aplicar todos los cambios." -ForegroundColor Green
Write-Host ""
pause
