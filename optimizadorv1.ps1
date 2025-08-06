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
    Write-Host " 06 - Restaurar Todo" -ForegroundColor White
    Write-Host " 07 - Salir" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Gray
    $opcion = Read-Host "Selecciona una opcion (01-07)"

    return $opcion
}

function Mostrar-Menu-Restaurar {
    do {
        Clear-Host
        Write-Host "=========================================================" -ForegroundColor Gray
        Write-Host "               MENU DE RESTAURACION DE SISTEMA" -ForegroundColor Red
        Write-Host "=========================================================" -ForegroundColor Gray
        Write-Host " 01 - Restaurar opciones del CPU" -ForegroundColor White
        Write-Host " 02 - Restaurar opciones del GPU" -ForegroundColor White
        Write-Host " 03 - Restaurar opciones de RED" -ForegroundColor White
        Write-Host " 04 - Restaurar opciones de Windows" -ForegroundColor White
        Write-Host " 05 - Volver al menu principal" -ForegroundColor Yellow
        Write-Host "=========================================================" -ForegroundColor Gray
        $opcion = Read-Host "Selecciona una opcion (01-05)"

        $opcion = $opcion.PadLeft(2, '0')

        switch ($opcion) {
            "01" { Restaurar-CPU }
            "02" { Restaurar-GPU }
            "03" { Restaurar-Red }
            "04" { Restaurar-Windows }
            "05" { return }  # Salir del submenú y volver al principal
            default {
                Write-Host "`nOpcion invalida. Selecciona entre 01 y 05." -ForegroundColor Red
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

        # EFECTOS VISUALES AVANZADOS
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

        # PLAN DE ENERGÍA
        Write-Host "Estableciendo plan de energia de maximo rendimiento..."
        powercfg -setactive SCHEME_MIN > $null
        powercfg -setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMAX 100 > $null
        powercfg -setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMIN 100 > $null

        # PRIVACIDAD Y TELEMETRÍA
        Write-Host "Desactivando telemetria y seguimiento..."
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

        # SERVICIOS
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

        # DESACTIVAR EXPLORADOR DE CARPETAS AUTOMATICO
        Write-Host "Desactivando descubrimiento automatico de carpetas..."
        reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell" /v BagMRU Size /t REG_DWORD /d 1 /f > $null

        # WIFI SENSE, STORAGE SENSE, FULLSCREEN OPTIMIZACIONES
        Write-Host "Desactivando WiFi Sense, Storage Sense, Recall y otros..."
        reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiSense" /v value /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f > $null

        # APPS EN SEGUNDO PLANO
        Write-Host "Desactivando apps en segundo plano..."
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

        # MINIATURAS Y SUAVIZADO
        Write-Host "`nAjustando miniaturas y fuentes..." -ForegroundColor Red
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f > $null

        # VISUALFX PERFORMANCE
        $regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        reg add "$regPath" /v VisualFXSetting /t REG_DWORD /d 2 /f > $null
        rundll32.exe user32.dll,UpdatePerUserSystemParameters

        Write-Host "`nTodas las optimizaciones de Windows han sido aplicadas correctamente." -ForegroundColor Green
    }
    catch {
        Write-Host "`nSe produjo un error durante la optimizacion: $_" -ForegroundColor Red
    }

    Pause
}

function Optimizar-Red {
    Clear-Host
    Write-Host ""
    Write-Host "   OPTIMIZACION AVANZADA DE RED - BY FKN AIDEN" -ForegroundColor Red
    Write-Host ""

   # Detectar adaptador activo
    $adapterActivo = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
    if (!$adapterActivo) {
        Write-Host "No se encontro un adaptador de red activo." -ForegroundColor Red
        Pause
        return
    }
    $adapterName = $adapterActivo.Name
    Write-Host "Adaptador activo detectado: $adapterName" -ForegroundColor Green
    Write-Host ""
    
    # 1. Desactivar ahorro de energía
    try {
        Write-Host "Desactivando ahorro de energia en el adaptador..."
        Disable-NetAdapterPowerManagement -Name $adapterName -ErrorAction Stop
        Write-Host "Completado" -ForegroundColor Green
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }

    # 2. Configuraciones TCP (modernas)
    $tcpSettings = @(
        @{Name="AutoTuning"; Value="restricted"},
        @{Name="RSS"; Value="disabled"},
        @{Name="ECN"; Value="enabled"},
        @{Name="InitialRTO"; Value="1000"}
    )

    foreach ($setting in $tcpSettings) {
        try {
            Write-Host "Configurando $($setting.Name)..."
            netsh int tcp set global $($setting.Name)=$($setting.Value)
            Write-Host "Completado" -ForegroundColor Green
        } catch {
            Write-Host "Error: $_" -ForegroundColor Red
        }
    }

    # 3. TCPNoDelay (Nagle Off)
    try {
        Write-Host "Activando TCPNoDelay..."
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
            Set-ItemProperty -Path $_.PsPath -Name "TcpAckFrequency" -Value 1 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $_.PsPath -Name "TCPNoDelay" -Value 1 -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Completado" -ForegroundColor Green
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }

        # 4. DNS y IP
    try {
        Write-Host "Limpiando cache DNS..."
        ipconfig /flushdns | Out-Null
        Write-Host "Completado" -ForegroundColor Green
        
        Write-Host "Configurando DNS (Cloudflare + Google)..."
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses @("1.1.1.1", "8.8.8.8") -ErrorAction Stop
        Write-Host "Completado" -ForegroundColor Green
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }

   # Array con todas las optimizaciones a aplicar
    $optimizations = @(
        @{
            Name = "Desactivando Teredo (IPv6 tunneling)";
            Command = "netsh interface teredo set state disabled";
            Description = "Mejora seguridad deshabilitando tunelización IPv6 innecesaria"
        },
        @{
            Name = "Deshabilitando ISATAP (IPv6 transitional)";
            Command = "netsh interface isatap set state disabled";
            Description = "Elimina protocolo de transicion IPv6 obsoleto"
        },
        @{
            Name = "Limitando ancho de banda para Windows Update";
            Command = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f';
            Description = "Previene que Updates consuma toda tu conexión"
        },
        @{
            Name = "Desactivando LLMNR (Protocolo de resolucion nombres)";
            Command = 'reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f';
            Description = "Evita ataques de spoofing y trafico innecesario"
        }
    )

    # Bucle para aplicar cada optimización
    foreach ($opt in $optimizations) {
        try {
            Write-Host ""
            Write-Host " [$($optimizations.IndexOf($opt)+1)/$($optimizations.Count)] $($opt.Name)" -ForegroundColor Yellow
            Write-Host "$($opt.Description)" -ForegroundColor Gray
            
            # Ejecutar el comando
            Invoke-Expression $opt.Command | Out-Null
            
            Write-Host "Configuracion aplicada correctamente" -ForegroundColor Green
        } catch {
            Write-Host " Error al aplicar: $_" -ForegroundColor Red
            Write-Host "! Intenta ejecutar como Administrador si persiste" -ForegroundColor DarkYellow
        }
    }


    Write-Host ""
    Write-Host "Optimizacion de red completada correctamente." -ForegroundColor Green
    Write-Host "Reinicia tu PC para aplicar todos los cambios correctamente." -ForegroundColor Yellow
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
    Write-Host ""
    Write-Host "Esta funcion restaurara configuraciones del sistema que fueron modificadas para la optimizacion." -ForegroundColor Yellow
    Write-Host ""
    $confirmacion = Read-Host "Deseas continuar con la restauracion de Windows? (S/N)"
    Write-Host ""
    if ($confirmacion -ne 'S' -and $confirmacion -ne 's') {
        Write-Host "Operacion cancelada por el usuario." -ForegroundColor Red
        return
    }

    try {
        Write-Host ""
        Write-Host "Restaurando configuraciones..." -ForegroundColor Cyan

        # Restaurar servicios
        Write-Host "Reactivando servicios importantes..."
        $servicios = @(
            "DiagTrack", "WSearch", "SysMain", "RetailDemo", "WMPNetworkSvc", "HomeGroupListener", "HomeGroupProvider", "OneSyncSvc", "TrkWks"
        )
        foreach ($serv in $servicios) {
            Set-Service -Name $serv -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $serv -ErrorAction SilentlyContinue
        }

        # Restaurar efectos visuales por defecto
        Write-Host "Restaurando efectos visuales..."
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9e1e078012000000 /f > $null

        # Restaurar plan de energia balanceado
        Write-Host "Restaurando plan de energia a Balanceado..."
        powercfg -setactive SCHEME_BALANCED > $null

        # Restaurar telemetría y privacidad
        Write-Host "Reactivando telemetría y seguimiento..."
        reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /f > $null
        reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f > $null
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /f > $null

        # Restaurar ubicación
        Write-Host "Reactivando ubicacion..."
        reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /f > $null

        # Restaurar WiFi Sense, Storage Sense, Game DVR
        Write-Host "Reactivando WiFi Sense y otras opciones..."
        reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiSense" /f > $null
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /f > $null
        reg delete "HKCU\System\GameConfigStore" /f > $null

        # Restaurar apps en segundo plano
        Write-Host "Reactivando aplicaciones en segundo plano..."
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /f > $null

        # Restaurar miniaturas y suavizado
        Write-Host "Restaurando miniaturas y suavizado de fuentes..."
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f > $null
        reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f > $null

        # Refrescar configuración visual
        rundll32.exe user32.dll,UpdatePerUserSystemParameters

        Write-Host ""
        Write-Host "Restauracion de Windows completada con exito." -ForegroundColor Green
    }
    catch {
        Write-Host ""
        Write-Host "Se produjo un error durante la restauracion: $_" -ForegroundColor Red
    }

    Pause
}

function Restaurar-Red {
    Clear-Host
    Write-Host ""
    Write-Host "   RESTAURACION DE CONFIGURACIONES DE RED - VALORES POR DEFECTO" -ForegroundColor Cyan
    Write-Host "   Esta función revertirá todas las optimizaciones aplicadas" -ForegroundColor Yellow
    Write-Host ""

    # Detectar adaptador activo
    $adapterActivo = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true } | Select-Object -First 1
    if (!$adapterActivo) {
        Write-Host "No se encontro un adaptador de red activo." -ForegroundColor Red
        Pause
        return
    }
    $adapterName = $adapterActivo.Name
    Write-Host "Adaptador seleccionado: $adapterName" -ForegroundColor Green
    Write-Host ""

    # 1. Restaurar configuración TCP global
    Write-Host "Restaurando configuracioon TCP global..." -ForegroundColor Yellow
    $tcpDefaults = @(
        "autotuninglevel=normal",
        "rss=enabled",
        "ecncapability=default",
        "initialrto=3000"
    )

    foreach ($setting in $tcpDefaults) {
        try {
            netsh interface tcp set global $setting | Out-Null
            Write-Host "$setting" -ForegroundColor Green
        } catch {
            Write-Host "Error al restaurar $setting" -ForegroundColor Red
        }
    }

    # 2. Restaurar MTU
    try {
        Write-Host "Restaurando MTU a valor por defecto (1500)..." -ForegroundColor Yellow
        netsh interface ipv4 set subinterface "$adapterName" mtu=1500 store=persistent
        Write-Host "MTU restaurado" -ForegroundColor Green
    } catch {
        Write-Host "Error al restaurar MTU" -ForegroundColor Red
    }

    # 3. Restaurar DNS a DHCP
    try {
        Write-Host "Restaurando DNS automatico (DHCP)..." -ForegroundColor Yellow
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ResetServerAddresses
        Write-Host "DNS restaurado" -ForegroundColor Green
    } catch {
        Write-Host "Error al restaurar DNS" -ForegroundColor Red
    }

    # 4. Restaurar Nagle Algorithm (TCPNoDelay)
    try {
        Write-Host "Restaurando algoritmo de Nagle..." -ForegroundColor Yellow
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
            Remove-ItemProperty -Path $_.PsPath -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $_.PsPath -Name "TCPNoDelay" -ErrorAction SilentlyContinue
        }
        Write-Host "Configuracion TCP restaurada" -ForegroundColor Green
    } catch {
        Write-Host "Error al restaurar configuracion TCP" -ForegroundColor Red
    }

    # 5. Reactivar protocolos
    $protocolos = @(
        @{Name="Teredo"; Command="netsh interface teredo set state default"},
        @{Name="ISATAP"; Command="netsh interface isatap set state enabled"}
    )

    foreach ($proto in $protocolos) {
        try {
            Write-Host "Restaurando $($proto.Name)..." -ForegroundColor Yellow
            Invoke-Expression $proto.Command | Out-Null
            Write-Host "$($proto.Name) restaurado" -ForegroundColor Green
        } catch {
            Write-Host "Error al restaurar $($proto.Name)" -ForegroundColor Red
        }
    }

    # 6. Restaurar configuración de Windows Update
    try {
        Write-Host "Restaurando configuracion de Windows Update..." -ForegroundColor Yellow
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
        Write-Host "Optimizacion de updates restaurada" -ForegroundColor Green
    } catch {
        Write-Host "Error al restaurar configuracion de updates" -ForegroundColor Red
    }

    # 7. Reactivar LLMNR
    try {
        Write-Host "Restaurando LLMNR..." -ForegroundColor Yellow
        Remove-ItemProperty -Path "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        Write-Host "LLMNR reactivado" -ForegroundColor Green
    } catch {
        Write-Host "Error al reactivar LLMNR" -ForegroundColor Red
    }

    # 8. Restaurar power management
    try {
        Write-Host "Restaurando configuracion de energia..." -ForegroundColor Yellow
        Enable-NetAdapterPowerManagement -Name $adapterName -ErrorAction SilentlyContinue
        Write-Host "Configuracion de energia restaurada" -ForegroundColor Green
    } catch {
        Write-Host "Error al restaurar configuracion de energia" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "Restauracion completada:" -ForegroundColor Cyan
    Write-Host "Todas las configuraciones de red fueron restauradas a valores por defecto" -ForegroundColor Green
    Write-Host "Reinicia tu equipo para aplicar todos los cambios completamente" -ForegroundColor Yellow
    Write-Host ""
    
    # Limpiar y renovar IP
    Write-Host "Limpiando configuracion de red..." -ForegroundColor Yellow
    ipconfig /flushdns | Out-Null
    ipconfig /release | Out-Null
    ipconfig /renew | Out-Null
    
    Write-Host ""
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
