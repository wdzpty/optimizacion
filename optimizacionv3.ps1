#Fuerza UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

# Visual
$host.UI.RawUI.WindowTitle = "Optimizador Avanzado - By Fkn Aiden"
$host.UI.RawUI.BackgroundColor = "Black"
$host.UI.RawUI.ForegroundColor = "Red"
Clear-Host

function Mostrar-Advertencia {
    Clear-Host

    # Definir colores
    $rojo = "Red"
    $blanco = "White"
    $gris = "Gray"

    Write-Host ""
    Write-Host "================================================================"-ForegroundColor $gris
    Write-Host "                     ADVERTENCIAS IMPORTANTES  " -ForegroundColor $rojo
     Write-Host "================================================================" -ForegroundColor $gris
    Write-Host ""

    Write-Host " - Este optimizador es totalmente libre de virus o software malicioso." -ForegroundColor $blanco
    Write-Host " - Algunas opciones podrían desactivarse tras una actualización de Windows." -ForegroundColor $gris
    Write-Host " - No hace magia: el rendimiento depende del hardware de tu PC." -ForegroundColor $blanco
    Write-Host " - Se recomienda crear un punto de restauración antes de continuar." -ForegroundColor $gris
    Write-Host " - Usa este script bajo tu propio criterio y responsabilidad." -ForegroundColor $blanco
    Write-Host ""

    Write-Host "================================================================" -ForegroundColor $gris
    Write-Host ""
    Write-Host " Presiona cualquier tecla para continuar..." -ForegroundColor $rojo
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}


function Mostrar-Menu {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host "              OPTIMIZADOR AVANZADO - BY FKN AIDEN" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host " 01 - Crear punto de restauracion" -ForegroundColor White
    Write-Host " 02 - Optimizar CPU" -ForegroundColor White
    Write-Host " 03 - Optimizar GPU" -ForegroundColor White
    Write-Host " 04 - Optimizar Windows" -ForegroundColor White
    Write-Host " 05 - Optimizar RED" -ForegroundColor White
    Write-Host " 06 - Salir" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Gray
    $opcion = Read-Host "Selecciona una opcion (01-06)"

    return $opcion
}

function Verificar-Administrador {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "`nERROR: Ejecuta este script como Administrador." -ForegroundColor Red
        Pause
        exit
    }
}

function Crear-RestorePoint {
    Write-Host "`nCrear punto de restauracion del sistema" -ForegroundColor Red
    $nombre = Read-Host "Escribe un nombre para el punto de restauracion"
    
    if ([string]::IsNullOrWhiteSpace($nombre)) {
        Write-Host "Nombre no valido. Operacion cancelada." -ForegroundColor Red
        Pause
        return
    }

    try {
        Write-Host "`nCreando punto de restauracion: '$nombre'..." -ForegroundColor Red
        Checkpoint-Computer -Description $nombre -RestorePointType "MODIFY_SETTINGS"
        Write-Host "Punto de restauracion '$nombre' creado correctamente." -ForegroundColor Gray
    } catch {
        Write-Host "Error al crear el punto de restauracion: $_" -ForegroundColor Red
    }

    Pause
}


function Optimizar-CPU {
    Write-Host "`nIniciando optimizacion de CPU..." -ForegroundColor Red

    # Activar plan de alto rendimiento
    Write-Host "Activando plan de energia de alto rendimiento..."
    $scheme = "SCHEME_MIN"
    Start-Process "powercfg.exe" -ArgumentList "-duplicatescheme $scheme" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setactive $scheme" -WindowStyle Hidden -Wait

    # Desbloquear nucleos de CPU
    Write-Host "Desbloqueando nucleos de CPU (modo ahorro desactivado)..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v Attributes /t REG_DWORD /d 0 /f > $null

    # Desactivar servicios innecesarios
    Write-Host "Desactivando servicios no criticos..."
    $services = @("DiagTrack", "SysMain", "WSearch", "dmwappushservice")
    foreach ($s in $services) {
        sc.exe config $s start= disabled | Out-Null
        sc.exe stop $s | Out-Null
    }

    # Desactivar tareas programadas
    Write-Host "Desactivando tareas programadas innecesarias..."
    $tasks = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    )
    foreach ($task in $tasks) {
        schtasks.exe /Change /TN $task /Disable > $null 2>&1
    }

    # Desactivar Cortana
    Write-Host "Desactivando Cortana..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f > $null

    # Desactivar GameDVR y GameBar
    Write-Host "Desactivando GameDVR y GameBar..."
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f > $null
    reg add "HKCU\Software\Microsoft\Windows\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f > $null

    # Prioridad a tareas en primer plano
    Write-Host "Ajustando prioridad para tareas en primer plano..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f > $null

    # Optimizar uso del CPU de forma saludable
    Write-Host "Optimizando uso del CPU de forma inteligente..."
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTMODE 2" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTPOLICY 2" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PROCTHROTTLEMIN 5" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PROCTHROTTLEMAX 100" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR IDLEDISABLE 0" -WindowStyle Hidden -Wait

    # Desactivar animaciones de Windows
    Write-Host "Desactivando animaciones de Windows..."
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f > $null

    Write-Host "`nOPTIMIZACION DE CPU COMPLETADA. Reinicia tu PC para aplicar los cambios." -ForegroundColor Red
    Pause
}

function Optimizar-GPU {
    Write-Host "`nDetectando tarjeta gráfica..." -ForegroundColor Red
    $gpuInfo = (Get-CimInstance Win32_VideoController).Name

    if ($gpuInfo -match "NVIDIA") {
        Write-Host "GPU NVIDIA detectada: $gpuInfo" -ForegroundColor White

        # Crear claves necesarias
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Force | Out-Null

        # Desactivar TDR
        Write-Host "Desactivando TDR (Timeout Detection and Recovery)..."
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 10 /f > $null
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f > $null

        # Habilitar modo de baja latencia y optimizar para rendimiento
        Write-Host "Optimizando configuraciones clave de NVIDIA..."
        reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v "DisableP2State" /t REG_DWORD /d 1 /f > $null
        reg add "HKCU\Software\NVIDIA Corporation\Global\NGC" /v "MaxFrameRate" /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\NVIDIA Corporation\Global\NGC" /v "LowLatencyMode" /t REG_DWORD /d 1 /f > $null

        Write-Host "`nOptimizacion aplicada para NVIDIA." -ForegroundColor Gray

    } elseif ($gpuInfo -match "AMD") {
        Write-Host "GPU AMD detectada: $gpuInfo" -ForegroundColor White

        # Desactivar TDR
        Write-Host "Desactivando TDR..."
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 10 /f > $null
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f > $null

        # Activar modo de rendimiento en drivers
        Write-Host "Optimizando configuraciones clave de AMD..."
        reg add "HKCU\Software\AMD\CN" /v "GameMode" /t REG_DWORD /d 1 /f > $null
        reg add "HKCU\Software\AMD\CN" /v "TuningControl" /t REG_DWORD /d 1 /f > $null

        Write-Host "`nOptimizacion aplicada para AMD." -ForegroundColor Gray

    } elseif ($gpuInfo -match "Intel" -or $gpuInfo -match "UHD" -or $gpuInfo -match "Iris" -or $gpuInfo -match "Radeon Graphics") {
        Write-Host "GPU integrada detectada: $gpuInfo" -ForegroundColor White

        # Desactivar TDR
        Write-Host "Desactivando TDR..."
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 10 /f > $null
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f > $null

        # Prioridad a GPU
        Write-Host "Estableciendo prioridad de procesamiento por GPU..."
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f > $null

        # Forzar aceleración por GPU en apps
        Write-Host "Forzando uso de GPU en aplicaciones..."
        reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "GpuPreference" /t REG_DWORD /d 2 /f > $null

        # Activar aceleración hardware en apps
        Write-Host "Habilitando aceleración por hardware..."
        reg add "HKCU\Software\Microsoft\Avalon.Graphics" /v DisableHWAcceleration /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Office\16.0\Common\Graphics" /v DisableHardwareAcceleration /t REG_DWORD /d 0 /f > $null

        Write-Host "`nOptimizacion aplicada para GPU integrada." -ForegroundColor Gray

    } else {
        Write-Host "No se pudo identificar la GPU o no es compatible." -ForegroundColor Yellow
    }

    Pause
}

function Optimizar-Windows {
    Clear-Host
    Write-Host "`nADVERTENCIA: Esta función aplicará cambios avanzados al sistema que podrían afectar componentes visuales, privacidad, servicios y configuraciones internas." -ForegroundColor Yellow
    Write-Host "Se recomienda crear un punto de restauración antes de continuar." -ForegroundColor Gray
    $confirmacion = Read-Host "`n¿Deseas continuar con la optimización completa de Windows? (S/N)"
    if ($confirmacion -ne 'S' -and $confirmacion -ne 's') {
        Write-Host "`nOperación cancelada por el usuario." -ForegroundColor Red
        return
    }

    try {
        Write-Host "`nIniciando optimización..." -ForegroundColor Red

        # ARCHIVOS TEMPORALES Y CACHÉ
        Write-Host "`nEliminando archivos temporales..." -ForegroundColor Gray
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue

        # RENDIMIENTO VISUAL
        Write-Host "Ajustando efectos visuales para rendimiento..."
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f > $null

        # PLAN DE ENERGÍA MÁXIMO RENDIMIENTO
        Write-Host "Estableciendo plan de energía de máximo rendimiento..."
        powercfg -setactive SCHEME_MIN > $null
        powercfg -setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMAX 100 > $null
        powercfg -setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMIN 100 > $null

        # PRIVACIDAD Y TELEMETRÍA
        Write-Host "Desactivando telemetría y seguimiento..."
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null

        # UBICACIÓN Y TRACKING
        Write-Host "Desactivando ubicación y seguimiento..."
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

        # SERVICIOS
        Write-Host "Estableciendo servicios innecesarios como manual o deshabilitado..."
        $servicios = @(
            "DiagTrack", "WSearch", "SysMain", "RetailDemo", "WMPNetworkSvc", "HomeGroupListener", "HomeGroupProvider", "OneSyncSvc", "TrkWks"
        )
        foreach ($serv in $servicios) {
            Set-Service -Name $serv -StartupType Manual -ErrorAction SilentlyContinue
            Stop-Service -Name $serv -Force -ErrorAction SilentlyContinue
        }

        # EXPLORADOR DE ARCHIVOS
        Write-Host "Desactivando descubrimiento automático de carpetas..."
        reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell" /v BagMRU Size /t REG_DWORD /d 1 /f > $null

        # WIFI SENSE, STORAGE SENSE, FULLSCREEN OPTIMIZACIONES
        Write-Host "Desactivando WiFi Sense, Storage Sense, Recall y otros..."
        reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiSense" /v value /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f > $null

        # APLICACIONES EN SEGUNDO PLANO
        Write-Host "Desactivando apps en segundo plano..."
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

        # MOSTRAR MINIATURAS Y SUAVIZADO DE FUENTES
        Write-Host "`nAjustando efectos visuales para mejor rendimiento..." -ForegroundColor Red

        # Mostrar vistas en miniatura
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 0 /f > $null

        # Suavizado de fuentes
        reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f > $null

        # Configurar para rendimiento personalizado (activar modo rendimiento personalizado)
        $regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        reg add "$regPath" /v VisualFXSetting /t REG_DWORD /d 3 /f > $null

        # Aplicar configuración para que Windows use "Ajustar para obtener el mejor rendimiento" 
        # y luego active solo lo necesario
        reg add $regPath /v VisualFXSetting /t REG_DWORD /d 2 /f > $null

        # Forzar que Windows reprocese estas configuraciones (refrescar visuales)
        rundll32.exe user32.dll,UpdatePerUserSystemParameters

        Write-Host "Miniaturas y suavizado de fuentes ajustados." -ForegroundColor Green

        Write-Host "`nTodas las optimizaciones de Windows han sido aplicadas correctamente." -ForegroundColor Green
    }
    catch {
        Write-Host "`nSe produjo un error durante la optimización: $_" -ForegroundColor Red
    }

    Pause
}

function Optimizar-Red {
    Write-Host "`nIniciando optimización de red para mejorar ping y latencia..." -ForegroundColor Red

    # Desactivar autotuning para evitar buffers excesivos que añaden latencia
    Write-Host "Desactivando autotuning del adaptador de red..."
    netsh interface tcp set global autotuninglevel=disabled

    # Desactivar la recepción selectiva para mejorar la latencia
    Write-Host "Desactivando recepción selectiva..."
    netsh interface tcp set global rss=disabled

    # Activar TCP no nagle para mejorar respuesta
    Write-Host "Activando TCP no nagle (deshabilitar nagle)..."
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -Name "TcpNoDelay" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

    # Activar TCP chimney offload para descarga de procesamiento al hardware
    Write-Host "Activando TCP chimney offload..."
    netsh int tcp set global chimney=enabled

    # Ajustar el MTU a valor óptimo común (normalmente 1472 o 1500)
    Write-Host "Estableciendo MTU a 1472..."
    # Nota: Cambia "Ethernet" por el nombre de tu adaptador de red
    $adapterName = "Ethernet"
    netsh interface ipv4 set subinterface "$adapterName" mtu=1472 store=persistent

    # Desactivar la mejora de la calidad de servicio para juegos
    Write-Host "Desactivando QoS Packet Scheduler para evitar limitación..."
    Set-NetQosFlow -PolicyStore ActiveStore -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue

    # Aumentar el tiempo de espera TCP
    Write-Host "Aumentando el tiempo de espera TCP para evitar latencia..."
    netsh int tcp set global delayedack=disabled

    Write-Host "`nOptimización de red aplicada con éxito." -ForegroundColor Green
    Pause
}


# --- EJECUCION ---
Verificar-Administrador
Mostrar-Advertencia

do {
    $seleccion = Mostrar-Menu
    
    # Normaliza la entrada (acepta "6" o "06")
    $seleccionNormalizada = $seleccion.PadLeft(2, '0')

    switch ($seleccionNormalizada) {
        "01" { Crear-RestorePoint }
        "02" { Optimizar-CPU }
        "03" { Optimizar-GPU }
        "04" { Optimizar-Windows }
        "05" { Optimizar-Red }
        "06" {
            Write-Host "`nSaliendo del optimizador. Hasta luego." -ForegroundColor Gray
            exit  # <-- Cierra PowerShell completamente
        }
        default {
            Write-Host "`nOpción inválida. Por favor selecciona entre 01 y 06." -ForegroundColor Red
            Pause
        }
    }
} while ($true)  # El bucle se rompe con 'exit' en la opción 6
