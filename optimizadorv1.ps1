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
    Write-Host "---------------------------------------------------------------------------"-ForegroundColor $gris
    Write-Host "                     ADVERTENCIAS IMPORTANTES                   " -ForegroundColor $rojo
    Write-Host "---------------------------------------------------------------------------" -ForegroundColor $gris
    Write-Host ""

    Write-Host " - Este optimizador es totalmente libre de virus o software malicioso." -ForegroundColor $blanco
    Write-Host " - Algunas opciones podrian desactivarse tras una actualizacion de Windows." -ForegroundColor $gris
    Write-Host " - No hace magia: el rendimiento depende del hardware de tu PC." -ForegroundColor $blanco
    Write-Host " - Se recomienda crear un punto de restauracion antes de continuar." -ForegroundColor $gris
    Write-Host " - Usa este script bajo tu propio criterio y responsabilidad." -ForegroundColor $blanco
    Write-Host ""

    Write-Host "---------------------------------------------------------------------------" -ForegroundColor $gris
    Write-Host ""
    Write-Host " Presiona cualquier tecla para continuar..." -ForegroundColor $rojo
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}


function Mostrar-Menu {
    Clear-Host
    Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "              OPTIMIZADOR AVANZADO - BY FKN AIDEN" -ForegroundColor Red
    Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " 01 - Crear punto de restauracion" -ForegroundColor White
    Write-Host " 02 - Optimizar CPU" -ForegroundColor White
    Write-Host " 03 - Optimizar GPU" -ForegroundColor White
    Write-Host " 04 - Optimizar Windows" -ForegroundColor White
    Write-Host " 05 - Optimizar RED" -ForegroundColor White
    Write-Host " 06 - Restaurar Todo" -ForegroundColor White
    Write-Host " 07 - Salir" -ForegroundColor White
    Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
    $opcion = Read-Host "Selecciona una opcion (01-07)"

    return $opcion
}

function Mostrar-Menu-Restaurar {
    do {
        Clear-Host
        Write-Host "---------------------------------------------------------" -ForegroundColor Gray
        Write-Host "               MENU DE RESTAURACION DE SISTEMA           " -ForegroundColor Red
        Write-Host "---------------------------------------------------------" -ForegroundColor Gray
        Write-Host " 01 - Restaurar opciones del CPU" -ForegroundColor White
        Write-Host " 02 - Restaurar opciones del GPU" -ForegroundColor White
        Write-Host " 03 - Restaurar opciones de RED" -ForegroundColor White
        Write-Host " 04 - Restaurar opciones de Windows" -ForegroundColor White
        Write-Host " 05 - Volver al menu principal" -ForegroundColor Yellow
        Write-Host "---------------------------------------------------------" -ForegroundColor Gray
        $opcion = Read-Host "Selecciona una opcion (01-05)"

        $opcion = $opcion.PadLeft(2, '0')

        switch ($opcion) {
            "01" { Restaurar-CPU }
            "02" { Restaurar-GPU }
            "03" { Restaurar-RedUniversal }
            "04" { Restaurar-Windows }
            "05" { return }  # Salir del submenú y volver al principal
            default {
                Write-Host ""
                Write-Host "Opcion invalida. Selecciona entre 01 y 05." -ForegroundColor Red
                Write-Host ""
                Pause
            }
        }
    } while ($true)
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
    Write-Host ""  # linea en blanco
    Write-Host "Iniciando optimizacion de CPU..." -ForegroundColor Red
    Write-Host ""  # linea en blanco

    # Plan de energia alto rendimiento
    Write-Host ""  # linea en blanco
    Write-Host "Activando plan de energia de alto rendimiento..."
    Write-Host ""  # linea en blanco
    $scheme = "SCHEME_MIN"
    Start-Process "powercfg.exe" -ArgumentList "-duplicatescheme $scheme" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setactive $scheme" -WindowStyle Hidden -Wait

    # Desbloquear todos los nucleos del CPU
    Write-Host "Desbloqueando todos los nucleos del CPU (modo ahorro desactivado)..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v Attributes /t REG_DWORD /d 0 /f > $null

    # Desactivar servicios que consumen CPU y no son criticos
    Write-Host ""  # linea en blanco
    Write-Host "Desactivando servicios en segundo plano innecesarios..."
    Write-Host ""  # linea en blanco
    $services = @("DiagTrack", "SysMain", "WSearch", "dmwappushservice")
    foreach ($s in $services) {
        sc.exe config $s start= disabled | Out-Null
        sc.exe stop $s | Out-Null
    }

    # Desactivar tareas programadas que reportan datos o generan carga innecesaria
    Write-Host "Desactivando tareas programadas innecesarias..."
    $tasks = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    )
    foreach ($task in $tasks) {
        schtasks.exe /Change /TN $task /Disable > $null 2>&1
    }

    # Desactivar funciones innecesarias del sistema
    Write-Host ""  # linea en blanco
    Write-Host "Desactivando funciones del sistema no esenciales..."
    Write-Host ""  # linea en blanco

    # Cortana
    Write-Host "- Cortana desactivado"
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f > $null

    # GameBar y GameDVR
    Write-Host "- GameBar y GameDVR desactivados"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f > $null
    reg add "HKCU\Software\Microsoft\Windows\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f > $null

    # OneDrive
    Write-Host "- Desactivando OneDrive"
    reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null

    # Animaciones de Windows
    Write-Host "- Animaciones visuales desactivadas"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f > $null

    # Transparencias
    Write-Host "- Efectos de transparencia desactivados"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f > $null

    # Limitar apps en segundo plano
    Write-Host "- Limitando apps en segundo plano"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

    # Notificaciones innecesarias
    Write-Host "- Notificaciones del sistema desactivadas"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f > $null

    # Inicio rapido
    Write-Host "- Desactivando inicio rapido"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f > $null

    # Prioridad a tareas en primer plano
    Write-Host "Asignando prioridad a tareas en primer plano..."
    Write-Host ""  # linea en blanco
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f > $null

    # Optimizacion avanzada de energia para CPU
    Write-Host "Aplicando ajustes avanzados de energia para el CPU..."
    Write-Host ""  # linea en blanco
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTMODE 2" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTPOLICY 2" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PROCTHROTTLEMIN 5" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PROCTHROTTLEMAX 100" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR IDLEDISABLE 0" -WindowStyle Hidden -Wait

    Write-Host ""  # linea en blanco
    Write-Host "OPTIMIZACION DE CPU COMPLETADA. Se recomienda reiniciar tu PC para aplicar los cambios." -ForegroundColor Red
    Write-Host ""  # linea en blanco
    Pause
}

function Optimizar-GPU {
    Write-Host ""  # linea en blanco
    Write-Host "Detectando tarjeta grafica..." -ForegroundColor Red
    Write-Host ""  # linea en blanco
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
       
        Write-Host ""  # linea en blanco
        Write-Host "Optimizacion aplicada para NVIDIA." -ForegroundColor Gray
        Write-Host ""  # linea en blanco

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

        Write-Host ""  # linea en blanco
        Write-Host "Optimizacion aplicada para AMD." -ForegroundColor Gray
        Write-Host ""  # linea en blanco

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
        Write-Host "Habilitando aceleracion por hardware..."
        reg add "HKCU\Software\Microsoft\Avalon.Graphics" /v DisableHWAcceleration /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Office\16.0\Common\Graphics" /v DisableHardwareAcceleration /t REG_DWORD /d 0 /f > $null

        Write-Host ""  # linea en blanco
        Write-Host "Optimizacion aplicada para GPU integrada." -ForegroundColor Gray
        Write-Host ""  # linea en blanco

    } else {
        Write-Host "No se pudo identificar la GPU o no es compatible." -ForegroundColor Yellow
    }

    Pause
}

function Optimizar-Windows {
    Clear-Host
    Write-Host ""  # linea en blanco
    Write-Host "ADVERTENCIA: Esta funcion aplicara cambios avanzados al sistema que podrian afectar componentes visuales, privacidad, servicios y configuraciones internas." -ForegroundColor Yellow
    Write-Host ""  # linea en blanco
    Write-Host "Se recomienda crear un punto de restauracion antes de continuar." -ForegroundColor Gray
    Write-Host ""  # linea en blanco
    $confirmacion = Read-Host "Deseas continuar con la optimizacion completa de Windows? (S/N)"
    Write-Host ""  # linea en blanco
    if ($confirmacion -ne 'S' -and $confirmacion -ne 's') {
        Write-Host "Operacion cancelada por el usuario." -ForegroundColor Red
        Write-Host ""  # linea en blanco
        return
    }

    try {
        Write-Host ""
        Write-Host "Iniciando optimizacion..." -ForegroundColor Red

        # ARCHIVOS TEMPORALES
        Write-Host "`nEliminando archivos temporales..." -ForegroundColor Gray
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue

        # EFECTOS VISUALES
        Write-Host "Ajustando efectos visuales para mejor rendimiento..."
        reg add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 200 /f > $null
        reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f > $null
        reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f > $null

        # PLAN DE ENERGIA
        Write-Host "Estableciendo plan de energia de maximo rendimiento..."
        powercfg -setactive SCHEME_MIN > $null
        powercfg -setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMAX 100 > $null
        powercfg -setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMIN 100 > $null

        # PRIVACIDAD Y TELEMETRIA
        Write-Host "Desactivando telemetria y seguimiento..."
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f > $null

        # SERVICIOS INNECESARIOS
        Write-Host "Estableciendo servicios innecesarios como manual o deshabilitado..."
        $servicios = @(
            "DiagTrack", "WSearch", "SysMain", "RetailDemo", "WMPNetworkSvc",
            "HomeGroupListener", "HomeGroupProvider", "OneSyncSvc", "TrkWks",
            "RemoteRegistry", "Fax", "MapsBroker", "XblGameSave", "XboxNetApiSvc"
        )
        foreach ($serv in $servicios) {
            try {
                Stop-Service -Name $serv -Force -ErrorAction SilentlyContinue
                Set-Service -Name $serv -StartupType Disabled -ErrorAction SilentlyContinue
            } catch {}
        }

        # CARPETAS AUTOMATICAS
        Write-Host "Desactivando descubrimiento automatico de carpetas..."
        reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell" /v BagMRU Size /t REG_DWORD /d 1 /f > $null

        # WIFI SENSE, STORAGE SENSE, GAME DVR
        Write-Host "Desactivando WiFi Sense, Storage Sense, Recall y otros..."
        reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiSense" /v value /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f > $null

        # APPS EN SEGUNDO PLANO
        Write-Host "Desactivando apps en segundo plano..."
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

        # MINIATURAS Y FUENTES
        Write-Host "`nAjustando miniaturas y fuentes..." -ForegroundColor Red
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f > $null

        # VISUALFX PERFORMANCE
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f > $null
        rundll32.exe user32.dll,UpdatePerUserSystemParameters

        Write-Host "`nTodas las optimizaciones de Windows han sido aplicadas correctamente." -ForegroundColor Green
    }
    catch {
        Write-Host "`nSe produjo un error durante la optimizacion: $_" -ForegroundColor Red
    }

    Pause
}

function Optimizar-RedUniversal {
    Clear-Host
    Write-Host "---------------------------------------------------------------" -ForegroundColor Red
    Write-Host "             OPTIMIZACION DE RED - BY FKN AIDEN                " -ForegroundColor White
    Write-Host "---------------------------------------------------------------" -ForegroundColor Red
    Write-Host ""

    # 1. Detectar adaptador activo (con validación mejorada)
    $adapterActivo = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
    if (!$adapterActivo) {
        Write-Host "No se encontro un adaptador de red activo." -ForegroundColor Red
        Pause
        return
    }
    $adapterName = $adapterActivo.Name
    $adapterSpeed = ($adapterActivo | Get-NetAdapterAdvancedProperty -RegistryKeyword "*SpeedDuplex").RegistryValue
    $isWifi = ($adapterActivo.InterfaceDescription -like "*Wireless*" -or $adapterActivo.Name -like "*Wi-Fi*")

    Write-Host "Adaptador detectado: $adapterName" -ForegroundColor White
    Write-Host "Tipo: $($isWifi ? 'Wi-Fi' : 'Ethernet')" -ForegroundColor White
    Write-Host "Velocidad: $($adapterSpeed -ge 1000 ? 'Alta (1Gbps+)' : 'Baja/Media (<1Gbps)')" -ForegroundColor White
    Write-Host ""

    # 2. Desactivar ahorro de energía (si no es una laptop en batería)
    $powerProfile = Get-WmiObject -Class Win32_Battery | Measure-Object | Select-Object -ExpandProperty Count
    if ($powerProfile -eq 0 -or (Get-CimInstance -ClassName Win32_Battery).BatteryStatus -eq 2) {
        Write-Host "PC en bateria: No se desactivara ahorro de energia." -ForegroundColor Red
    } else {
        try {
            Write-Host "Desactivando ahorro de energia en el adaptador..."
            Disable-NetAdapterPowerManagement -Name $adapterName -ErrorAction Stop
            Write-Host "Completado" -ForegroundColor White
        } catch {
            Write-Host "Error: $_" -ForegroundColor Red
        }
    }

    # 3. Configuraciones TCP (inteligentes según velocidad)
    $tcpSettings = @(
        @{Name="AutoTuning"; Value=($adapterSpeed -ge 1000 ? "normal" : "restricted"); Description="Ajuste dinamico de ventana TCP"},
        @{Name="ECN"; Value="enabled"; Description="Mejora congestión en redes modernas"},
        @{Name="InitialRTO"; Value="1000"; Description="Reduce tiempo de retransmision"}
    )

    # Solo desactivar RSS si la red es lenta (<1Gbps)
    if ($adapterSpeed -lt 1000) {
        $tcpSettings += @{Name="RSS"; Value="disabled"; Description="Mejor para redes lentas"}
    } else {
        $tcpSettings += @{Name="RSS"; Value="enabled"; Description="Optimizado para redes rapidas (1Gbps+)"}
    }

    foreach ($setting in $tcpSettings) {
        try {
            Write-Host "Configurando $($setting.Name) ($($setting.Description))..."
            netsh int tcp set global $($setting.Name)=$($setting.Value) | Out-Null
            Write-Host "Valor aplicado: $($setting.Value)" -ForegroundColor White
        } catch {
            Write-Host "Error: $_" -ForegroundColor Red
        }
    }

    # 4. TCPNoDelay (solo si no es Wi-Fi o el usuario lo fuerza)
    if (-not $isWifi -or (Read-Host "Forzar TCPNoDelay (recomendado para gaming)? [S/N]") -eq "S") {
        try {
            Write-Host "Activando TCPNoDelay (Nagle Off)..."
            Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
                Set-ItemProperty -Path $_.PsPath -Name "TcpAckFrequency" -Value 1 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $_.PsPath -Name "TCPNoDelay" -Value 1 -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Completado" -ForegroundColor Whie
        } catch {
            Write-Host "Error: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "TCPNoDelay no se aplico (puede aumentar latencia en Wi-Fi)." -ForegroundColor White
    }

    # 5. DNS (usar Cloudflare + Google por defecto, pero con opción personalizada)
    $customDNS = Read-Host "Usar DNS personalizados? (Dejar vacio para Cloudflare + Google)"
    try {
        Write-Host "Limpiando cache DNS..."
        ipconfig /flushdns | Out-Null
        if ($customDNS) {
            Write-Host "Configurando DNS personalizados: $customDNS"
            Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses $customDNS.Split(',')
        } else {
            Write-Host "Configurando DNS (Cloudflare + Google)..."
            Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses @("1.1.1.1", "8.8.8.8")
        }
        Write-Host "Completado" -ForegroundColor White
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }

    # 6. Optimizaciones adicionales (seguridad/rendimiento)
    $optimizations = @(
        @{Name="Desactivar Teredo"; Command="netsh interface teredo set state disabled"; Condition=$true},
        @{Name="Desactivar ISATAP"; Command="netsh interface isatap set state disabled"; Condition=$true},
        @{Name="Limitar ancho de banda de Windows Update"; Command='reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f'; Condition=$true},
        @{Name="Desactivar LLMNR"; Command='reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f'; Condition=(-not $isWifi)}
    )

    foreach ($opt in $optimizations) {
        if ($opt.Condition) {
            try {
                Write-Host ""
                Write-Host "Aplicando: $($opt.Name)" -ForegroundColor White
                Invoke-Expression $opt.Command | Out-Null
                Write-Host "Completado" -ForegroundColor White
            } catch {
                Write-Host "Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Saltando: $($opt.Name) (no aplicable)" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "Optimizacion completada." -ForegroundColor White
    Write-Host "Algunos cambios requieren reinicio (ejecuta 'Restart-Computer' si es necesario)." -ForegroundColor White
    Write-Host ""
    Pause
}

function Restaurar-CPU {
    Write-Host ""  # linea en blanco
    Write-Host "Iniciando restauracion de configuraciones del CPU..." -ForegroundColor Cyan
    Write-Host ""  # linea en blanco

    # Restaurar plan de energia a 'balanceado'
    Write-Host "Restaurando plan de energia balanceado..."
    Start-Process "powercfg.exe" -ArgumentList "-setactive SCHEME_BALANCED" -WindowStyle Hidden -Wait

    # Restaurar configuracion de nucleos del CPU
    Write-Host "Restaurando configuracion de ahorro de energia en nucleos..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v Attributes /t REG_DWORD /d 1 /f > $null

    # Restaurar servicios desactivados
    Write-Host ""  # linea en blanco
    Write-Host "Reactivando servicios importantes..."
    $services = @("DiagTrack", "SysMain", "WSearch", "dmwappushservice")
    foreach ($s in $services) {
        sc.exe config $s start= delayed-auto | Out-Null
    }

    # Restaurar tareas programadas
    Write-Host "Reactivando tareas programadas del sistema..."
    $tasks = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    )
    foreach ($task in $tasks) {
        schtasks.exe /Change /TN $task /Enable > $null 2>&1
    }

    # Restaurar funciones del sistema
    Write-Host ""  # linea en blanco
    Write-Host "Restaurando funciones del sistema..."
    
    # Cortana
    Write-Host "- Cortana activado"
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /f > $null 2>&1

    # GameBar y GameDVR
    Write-Host "- GameBar y GameDVR activados"
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /f > $null 2>&1
    reg delete "HKCU\Software\Microsoft\Windows\GameBar" /v AllowAutoGameMode /f > $null 2>&1

    # OneDrive
    Write-Host "- OneDrive habilitado"
    reg delete "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /f > $null 2>&1

    # Animaciones
    Write-Host "- Animaciones visuales activadas"
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /f > $null 2>&1

    # Transparencias
    Write-Host "- Efectos de transparencia activados"
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f > $null

    # Apps en segundo plano
    Write-Host "- Apps en segundo plano habilitadas"
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /f > $null 2>&1

    # Notificaciones
    Write-Host "- Notificaciones del sistema habilitadas"
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /f > $null 2>&1

    # Inicio rapido
    Write-Host "- Habilitando inicio rapido"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 1 /f > $null

    # Prioridad por defecto
    Write-Host "- Restaurando prioridad de tareas al valor por defecto"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 2 /f > $null

    # Restaurar configuracion avanzada de energia del CPU
    Write-Host ""  # linea en blanco
    Write-Host "Restaurando configuracion de energia avanzada del CPU..."
    $scheme = "SCHEME_BALANCED"
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTMODE 1" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTPOLICY 1" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PROCTHROTTLEMIN 1" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR PROCTHROTTLEMAX 100" -WindowStyle Hidden -Wait
    Start-Process "powercfg.exe" -ArgumentList "-setacvalueindex $scheme SUB_PROCESSOR IDLEDISABLE 1" -WindowStyle Hidden -Wait

    Write-Host ""  # linea en blanco
    Write-Host "RESTAURACION DE CPU COMPLETADA. Se recomienda reiniciar tu PC." -ForegroundColor Cyan
    Write-Host ""  # linea en blanco
    Pause
}

function Restaurar-GPU {
    Write-Host ""  # línea en blanco
    Write-Host "Restaurando configuraciones de la GPU..." -ForegroundColor Red
    Write-Host ""  # línea en blanco

    $gpuInfo = (Get-CimInstance Win32_VideoController).Name

    # Restaurar TDR (valores por defecto)
    Write-Host "Restableciendo valores TDR (Timeout Detection and Recovery)..."
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /f > $null 2>&1
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /f > $null 2>&1

    if ($gpuInfo -match "NVIDIA") {
        Write-Host "GPU NVIDIA detectada: $gpuInfo" -ForegroundColor White

        Write-Host "Restaurando configuraciones de NVIDIA..."

        reg delete "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v "DisableP2State" /f > $null 2>&1
        reg delete "HKCU\Software\NVIDIA Corporation\Global\NGC" /v "MaxFrameRate" /f > $null 2>&1
        reg delete "HKCU\Software\NVIDIA Corporation\Global\NGC" /v "LowLatencyMode" /f > $null 2>&1

    } elseif ($gpuInfo -match "AMD") {
        Write-Host "GPU AMD detectada: $gpuInfo" -ForegroundColor White

        Write-Host "Restaurando configuraciones de AMD..."

        reg delete "HKCU\Software\AMD\CN" /v "GameMode" /f > $null 2>&1
        reg delete "HKCU\Software\AMD\CN" /v "TuningControl" /f > $null 2>&1

    } elseif ($gpuInfo -match "Intel" -or $gpuInfo -match "UHD" -or $gpuInfo -match "Iris" -or $gpuInfo -match "Radeon Graphics") {
        Write-Host "GPU integrada detectada: $gpuInfo" -ForegroundColor White

        Write-Host "Restaurando configuraciones para GPU integrada..."

        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /f > $null 2>&1
        reg delete "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "GpuPreference" /f > $null 2>&1
        reg delete "HKCU\Software\Microsoft\Avalon.Graphics" /v DisableHWAcceleration /f > $null 2>&1
        reg delete "HKCU\Software\Microsoft\Office\16.0\Common\Graphics" /v DisableHardwareAcceleration /f > $null 2>&1

    } else {
        Write-Host "No se pudo identificar la GPU o no es compatible." -ForegroundColor Yellow
    }

    Write-Host ""  # línea en blanco
    Write-Host "Restauración de GPU completada." -ForegroundColor Gray
    Write-Host ""  # línea en blanco

    Pause
}

function Restaurar-Windows {
    Clear-Host
    Write-Host "-----------------------------------------------------------------------" -ForegroundColor Red
    Write-Host "          Restauracion del windows a estado predeterminado             " -ForegroundColor White
    Write-Host "-----------------------------------------------------------------------" -ForegroundColor Red
    Write-Host ""
    Write-Host "Esta funciOn restaurarA configuraciones modificadas por el optimizador." -ForegroundColor White
    Write-Host ""

    $confirmacion = Read-Host "Deseas continuar con la restauracion de Windows? (S/N)"
    if ($confirmacion -notin @('S','s')) {
        Write-Host ""
        Write-Host "Operacion cancelada por el usuario." -ForegroundColor Red
        Write-Host ""
        return
    }

    try {
        Write-Host ""
        Write-Host "[+] Restaurando configuraciones del sistema..." -ForegroundColor White

        # Restaurar servicios importantes
        Write-Host "  -> Reactivando servicios esenciales..." -ForegroundColor White
        $servicios = @(
            "DiagTrack", "WSearch", "SysMain", "RetailDemo",
            "WMPNetworkSvc", "HomeGroupListener", "HomeGroupProvider",
            "OneSyncSvc", "TrkWks"
        )
        foreach ($serv in $servicios) {
            Set-Service -Name $serv -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $serv -ErrorAction SilentlyContinue
        }

        # Restaurar efectos visuales
        Write-Host "  -> Restaurando efectos visuales por defecto..." -ForegroundColor White
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9e1e078012000000 /f > $null

        # Restaurar plan de energía
        Write-Host "  -> Restaurando plan de energia: Balanceado..." -ForegroundColor White
        powercfg -setactive SCHEME_BALANCED > $null

        # Restaurar configuración de telemetría y privacidad
        Write-Host "  -> Reactivando telemetria y seguimiento..." -ForegroundColor White
        reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /f > $null
        reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f > $null
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /f > $null

        # Restaurar ubicación
        Write-Host "  -> Restaurando configuracion de ubicacion..." -ForegroundColor White
        reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /f > $null

        # Restaurar configuraciones relacionadas
        Write-Host "  -> Restaurando WiFi Sense, Game DVR y Storage Sense..." -ForegroundColor White
        reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiSense" /f > $null
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /f > $null
        reg delete "HKCU\System\GameConfigStore" /f > $null

        # Restaurar apps en segundo plano
        Write-Host "  -> Reactivando aplicaciones en segundo plano..." -ForegroundColor White
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /f > $null

        # Restaurar miniaturas y suavizado de fuentes
        Write-Host "  -> Restaurando miniaturas y suavizado de fuentes..." -ForegroundColor White
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f > $null

        # Forzar actualización de parámetros visuales
        rundll32.exe user32.dll,UpdatePerUserSystemParameters

        Write-Host ""
        Write-Host "Restauracion de Windows completada con exito." -ForegroundColor Red
    }
    catch {
        Write-Host ""
        Write-Host "Se produjo un error durante la restauracion: $_" -ForegroundColor Red
    }

    Pause
}

function Restaurar-RedUniversal {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [switch]$ForzarRestauracion
    )

    Clear-Host
    Write-Host "------------------------------------------------------------" -ForegroundColor Red
    Write-Host "     RESTAURADOR UNIVERSAL DE RED (VALORES POR DEFECTO)     " -ForegroundColor White
    Write-Host "------------------------------------------------------------" -ForegroundColor Red
    Write-Host "   Esta funcion revertira todas las optimizaciones aplicadas" -ForegroundColor Gray
    Write-Host "   [!] Algunos cambios requieren reinicio" -ForegroundColor Red
    Write-Host ""

    # 1. Detección inteligente del adaptador
    try {
        $adapterActivo = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ErrorAction Stop
        if (-not $adapterActivo) {
            throw "No se encontro adaptador activo"
        }
        $adapterName = $adapterActivo.Name
        $isWifi = ($adapterActivo.InterfaceDescription -match "Wireless|Wi-Fi")
        
        Write-Host "Adaptador seleccionado:" -NoNewline
        Write-Host " $adapterName " -ForegroundColor Green -NoNewline
        Write-Host "($($isWifi ? 'Wi-Fi' : 'Ethernet'))"
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        Pause
        return
    }

    # 2. Confirmación antes de proceder (excepto si se usa -ForzarRestauracion)
    if (-not $ForzarRestauracion) {
        $confirmacion = Read-Host "Continuar con la restauracion? [S/N]"
        if ($confirmacion -ne "S") {
            Write-Host "Restauracion cancelada" -ForegroundColor Yellow
            return
        }
    }

    # 3. Restaurar configuración TCP global (con valores estándar de Microsoft)
    $tcpDefaults = @(
        @{Name="autotuninglevel"; Value="normal"; Desc="Optimizacion automatica TCP"},
        @{Name="rss"; Value="enabled"; Desc="Receive Side Scaling"},
        @{Name="ecncapability"; Value="default"; Desc="Explicit Congestion Notification"},
        @{Name="initialrto"; Value="3000"; Desc="Tiempo de reintento inicial (ms)"},
        @{Name="chimney"; Value="disabled"; Desc="Offload TCP (compatibilidad)"}
    )

    Write-Host "`n🔧 Restaurando configuración TCP global..." -ForegroundColor Yellow
    foreach ($setting in $tcpDefaults) {
        try {
            netsh int tcp set global $($setting.Name)=$($setting.Value) | Out-Null
            Write-Host "$($setting.Name.PadRight(15)) $($setting.Desc)" -ForegroundColor Gray
        } catch {
            Write-Host "$($setting.Name): Error al restaurar" -ForegroundColor Red
        }
    }

    # 4. Restaurar configuración de interfaz
    $interfaceSettings = @(
        @{Action="MTU"; Command="netsh interface ipv4 set subinterface `"$adapterName`" mtu=1500 store=persistent"; Desc="Tamano maximo de paquetes"},
        @{Action="DNS"; Command="Set-DnsClientServerAddress -InterfaceAlias `"$adapterName`" -ResetServerAddresses"; Desc="Servidores DNS (DHCP)"},
        @{Action="Energy"; Command="Enable-NetAdapterPowerManagement -Name `"$adapterName`""; Desc="Ahorro de energia"}
    )

    foreach ($setting in $interfaceSettings) {
        try {
            Write-Host "Restaurando $($setting.Action)..." -ForegroundColor Grey
            Write-Host ""
            Invoke-Expression $setting.Command | Out-Null
            Write-Host "$($setting.Desc)" -ForegroundColor White
        } catch {
            Write-Host "Error al restaurar $($setting.Action)" -ForegroundColor Red
        }
    }

    # 5. Restaurar configuraciones del registro (Nagle, protocolos, etc.)
    $registrySettings = @(
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"; Keys=@("TcpAckFrequency", "TCPNoDelay"); Desc="Algoritmo de Nagle"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Keys=@("DODownloadMode"); Desc="Optimizacion de updates"},
        @{Path="HKLM\Software\Policies\Microsoft\Windows NT\DNSClient"; Keys=@("EnableMulticast"); Desc="Protocolo LLMNR"}
    )

    Write-Host ""
    Write-Host "Restaurando configuraciones del registro..." -ForegroundColor White
    Write-Host ""
    foreach ($reg in $registrySettings) {
        try {
            if (Test-Path $reg.Path) {
                foreach ($key in $reg.Keys) {
                    Remove-ItemProperty -Path $reg.Path -Name $key -ErrorAction SilentlyContinue
                }
                Write-Host "$($reg.Desc)" -ForegroundColor White
            } else {
                Write-Host "$($reg.Desc): Ruta no encontrada" -ForegroundColor Gray
            }
        } catch {
            Write-Host "Error al restaurar $($reg.Desc)" -ForegroundColor Red
        }
    }

    # 6. Reactivar protocolos de red
    $protocolos = @(
        @{Name="Teredo"; Command="netsh interface teredo set state default"; Desc="Tunelizacion IPv6"},
        @{Name="ISATAP"; Command="netsh interface isatap set state enabled"; Desc="Transicion IPv6"}
    )

    foreach ($proto in $protocolos) {
        try {
            Write-Host ""
            Write-Host "Reactivando $($proto.Name)..." -ForegroundColor White
            Write-Host ""
            Invoke-Expression $proto.Command | Out-Null
            Write-Host "$($proto.Desc)" -ForegroundColor Gray
        } catch {
            Write-Host "Error al reactivar $($proto.Name)" -ForegroundColor Red
        }
    }

    # 7. Limpieza final
    Write-Host ""
    Write-Host "Limpieza final de red..." -ForegroundColor White
    Write-Host ""
    $cleanCommands = @(
        @{Command="ipconfig /flushdns"; Desc="Cache DNS"},
        @{Command="ipconfig /release"; Desc="Direccion IP"},
        @{Command="ipconfig /renew"; Desc="Nueva IP"}
    )

    foreach ($cmd in $cleanCommands) {
        try {
            Invoke-Expression $cmd.Command | Out-Null
            Write-Host "$($cmd.Desc) limpiada" -ForegroundColor White
        } catch {
            Write-Host "Error al limpiar $($cmd.Desc)" -ForegroundColor Red
        }
    }

    # Resultado final
    Write-Host ""
    Write-Host "RESTAURACION COMPLETADA" -ForegroundColor White
    Write-Host "Algunos cambios requieren reinicio para aplicar completamente" -ForegroundColor White
    Write-Host "Ejecuta 'Restart-Computer' cuando sea conveniente" -ForegroundColor Gray
    Write-Host ""
    
    # Opción para reiniciar inmediatamente
    if ($ForzarRestauracion -or (Read-Host "Reiniciar ahora? [S/N]") -eq "S") {
        Restart-Computer -Confirm
    } else {
        Pause
    }
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
        "05" { Optimizar-RedUniversal }
        "06" { Mostrar-Menu-Restaurar }
        "07" {
            Write-Host ""  # línea en blanco
            Write-Host "Saliendo del optimizador. Hasta luego." -ForegroundColor Gray
            exit  # Cierra PowerShell completamente
        }
        default {
            Write-Host ""  # línea en blanco
            Write-Host "Opcion invalida. Por favor selecciona entre 01 y 07." -ForegroundColor Red
            Pause
        }
    }
} while ($true)
