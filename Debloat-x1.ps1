   
#System Checking And Will run Auto*


#bloatware remover tool v2.5.


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "Welcome To Bloatware Remover Ver 2.5 By Ox1de. Please wait 5 sec and click yes."
    Start-Sleep 1
    Write-Host "                                               5"
    Start-Sleep 1
    Write-Host "                                               4"
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
	Write-Host "                                 	       1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit


}

write-host "Please wait until finished!"
Start-Sleep 1

Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.3DBuilder | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftOfficeHub | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.SkypeApp | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.WindowsMaps | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.Office.OneNote | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.XboxApp | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.BingSports | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.BingNews | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.BingFinance | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.WindowsAlarms | Remove-AppxPackage

Get-AppxPackage -AllUsers -Name Microsoft.People | Remove-AppxPackage

get-appxpackage *xbox* | remove-appxpackage

Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage 






Write-Host "Installing Subsystem For Linux WSL2"

if ($RU)
{
	$Title = "Windows Subsystem for Linux"
	$Message = "Чтобы установить Windows Subsystem for Linux, введите необходимую букву"
	$Options = "&Установить", "&Пропустить"
}
else
{
	$Title = "Windows Subsystem for Linux"
	$Message = "To install the Windows Subsystem for Linux enter the required letter"
	$Options = "&Install", "&Skip"
}
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		# Enable the Windows Subsystem for Linux
		# Включить подсистему Windows для Linux
		Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
		# Enable Virtual Machine Platform
		# Включить поддержку платформы для виртуальных машин
		Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart

		# Downloading the Linux kernel update package
		# Скачиваем пакет обновления ядра Linux
		try
		{
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
			{
				$Parameters = @{
					Uri = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
					OutFile = "$PSScriptRoot\wsl_update_x64.msi"
					Verbose = [switch]::Present
				}
				Invoke-WebRequest @Parameters

				Start-Process -FilePath $PSScriptRoot\wsl_update_x64.msi -ArgumentList "/passive" -Wait
				Remove-Item -Path $PSScriptRoot\wsl_update_x64.msi -Force
			}
		}
		catch
		{
			if ($Error.Exception.Status -eq "NameResolutionFailure")
			{
				if ($RU)
				{
					Write-Warning -Message "Отсутствует интернет-соединение" -ErrorAction SilentlyContinue
				}
				else
				{
					Write-Warning -Message "No Internet connection" -ErrorAction SilentlyContinue
				}
			}
		}

		<#
		# Comment out only after installing the Windows Subsystem for Linux
		# Раскомментируйте только после установки подсистемы Windows для Linux

		# Set WSL 2 as your default version. Run the command only after restart
		# Установить WSL 2 как версию по умолчанию. Выполните команду только после перезагрузки
		wsl --set-default-version 2

		# Configuring .wslconfig
		# Настраиваем .wslconfig
		# https://github.com/microsoft/WSL/issues/5437
		if (-not (Test-Path -Path "$env:HOMEPATH\.wslconfig"))
		{
			$wslconfig = @"
[wsl2]
swap=0
"@
			# Saving .wslconfig in UTF-8 encoding
			# Сохраняем .wslconfig в кодировке UTF-8
			Set-Content -Path "$env:HOMEPATH\.wslconfig" -Value (New-Object System.Text.UTF8Encoding).GetBytes($wslconfig) -Encoding Byte -Force
		}
		else
		{
			$String = Get-Content -Path "$env:HOMEPATH\.wslconfig" | Select-String -Pattern "swap=" -SimpleMatch
			if ($String)
			{
				(Get-Content -Path "$env:HOMEPATH\.wslconfig").Replace("swap=1", "swap=0") | Set-Content -Path "$env:HOMEPATH\.wslconfig" -Force
			}
			else
			{
				Add-Content -Path "$env:HOMEPATH\.wslconfig" -Value "`r`nswap=0" -Force
			}
		}
		#>
	}
	"1"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}




Write-Host "Shut the fuckuping the background apps"
Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
	Remove-ItemProperty -Path $_.PsPath -Name * -Force
}
$ExcludedBackgroundApps = @(
	# Lock App
	"Microsoft.LockApp*"
	# Content Delivery Manager
	"Microsoft.Windows.ContentDeliveryManager*"
	# Cortana
	"Microsoft.Windows.Cortana*"
	# Windows Search
	"Microsoft.Windows.Search*"
	# Windows Security
	# Безопасность Windows
	"Microsoft.Windows.SecHealthUI*"
	# ShellExperienceHost
	"Microsoft.Windows.ShellExperienceHost*"
	# StartMenuExperienceHost
	"Microsoft.Windows.StartMenuExperienceHost*"
	# Microsoft Store
	"Microsoft.WindowsStore*"
)
$OFS = "|"
Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | Where-Object -FilterScript {$_.PSChildName -cnotmatch $ExcludedBackgroundApps} | ForEach-Object -Process {
	New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
}
$OFS = " "
# Open "Background apps" page
# Открыть раздел "Фоновые приложения"
Start-Process -FilePath ms-settings:privacy-backgroundapps



Write-Host "Turn on the Sandbox"
if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -like "Enterprise*"})
{
	# Checking whether a x86 virtualization is enabled in BIOS
	# Проверка: включена ли в BIOS аппаратная виртуализация x86
	if ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled -eq $true)
	{
		Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart
	}
	else
	{
		try
		{
			# Determining whether a Hyper-V is enabled
			# Проверка: включен ли Hyper-V
			if ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent -eq $true)
			{
				Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart
			}
		}
		catch [Exception]
		{
			if ($RU)
			{
				Write-Error -Message "Включите в BIOS виртуализацию" -ErrorAction SilentlyContinue
			}
			else
			{
				Write-Error -Message "Enable Virtualization in BIOS" -ErrorAction SilentlyContinue
			}
		}
	}
}



Write-Host "Unpinning All the shortcuts from Start Menu"


	{
		$StartMenuLayout = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
	<DefaultLayoutOverride>
		<StartLayoutCollection>
			<defaultlayout:StartLayout GroupCellWidth="6" />
		</StartLayoutCollection>
	</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
		$StartMenuLayoutPath = "$env:TEMP\StartMenuLayout.xml"
		# Saving StartMenuLayout.xml in UTF-8 encoding
		# Сохраняем StartMenuLayout.xml в кодировке UTF-8
		Set-Content -Path $StartMenuLayoutPath -Value (New-Object System.Text.UTF8Encoding).GetBytes($StartMenuLayout) -Encoding Byte -Force

		# Temporarily disable changing Start layout
		# Временно выключаем возможность редактировать начальный экран
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
		{
			New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Value 1 -Force
		New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Value $StartMenuLayoutPath -Force

		# Restart the Start menu
		# Перезапустить меню "Пуск"
		Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore
		Start-Sleep -Seconds 3

		Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Force
		Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Force

		Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore
		Remove-Item -LiteralPath $StartMenuLayoutPath -Force
	}
	






    Write-Host "Creating Restore Point incase something bad happens"
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "Enabling Showing File Extension"
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force
    Write-Host "Disabling Recent Files in Quick Access"
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 0 -Force
    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Write-Host "Disabling Application suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0F
    Write-Host "Disabling Location Tracking..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Write-Host "Restricting Windows Update P2P only to local network..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Stopping and disabling Home Groups services..."
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    Write-Host "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

	# Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

	# SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304

    Write-Host "Disable News and Interests"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0

    Write-Host "Essential Tweaks Completed"