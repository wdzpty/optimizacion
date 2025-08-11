# Optimización extrema de CPU para gaming
# Advertencia: Puede afectar funciones de Windows no esenciales.
# Ejecútalo en PowerShell como Administrador.

# 1. Cambiar a plan de energía máximo
Write-Host "Aplicando plan de energía Máximo Rendimiento..." -ForegroundColor Cyan
powercfg -setactive SCHEME_MIN

# 2. Desactivar servicios innecesarios temporalmente
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
    Write-Host "Deteniendo servicio: $serv" -ForegroundColor Yellow
    Stop-Service -Name $serv -Force -ErrorAction SilentlyContinue
    Set-Service -Name $serv -StartupType Disabled -ErrorAction SilentlyContinue
}

# 3. Ajustar prioridad de juegos automáticamente
Write-Host "Aumentando prioridad de procesos de juegos conocidos..." -ForegroundColor Cyan
$Juegos = "FiveM_GTAProcess.exe","FortniteClient-Win64-Shipping.exe","VALORANT-Win64-Shipping.exe"
foreach ($juego in $Juegos) {
    $proc = Get-Process | Where-Object { $_.ProcessName -like "*$($juego.Split('.')[0])*" }
    if ($proc) {
        Write-Host "Cambiando prioridad de $($proc.ProcessName) a Alta" -ForegroundColor Green
        $proc.PriorityClass = "High"
    }
}

# 4. Ajustar afinidad de CPU para juegos (usar todos los núcleos)
foreach ($juego in $Juegos) {
    $proc = Get-Process | Where-Object { $_.ProcessName -like "*$($juego.Split('.')[0])*" }
    if ($proc) {
        $mask = [int]([math]::Pow(2, [Environment]::ProcessorCount) - 1)
        $proc.ProcessorAffinity = $mask
    }
}

# 5. Optimizar uso de CPU y latencia
Write-Host "Reduciendo latencia del sistema..." -ForegroundColor Cyan
bcdedit /set disabledynamictick yes
bcdedit /set useplatformclock true
bcdedit /set tscsyncpolicy Enhanced

Write-Host ""
Write-Host "Optimización completada. Reinicia el PC para aplicar todos los cambios." -ForegroundColor Green
Write-Host ""
pause
