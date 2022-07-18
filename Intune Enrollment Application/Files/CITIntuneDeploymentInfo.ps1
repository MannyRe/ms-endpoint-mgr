<#
.SYNOPSIS
	This script performs some functions to help enroll the current device into Intune and perform troubleshootig and send logs.
.DESCRIPTION
	The script will perform the following actions:
        Backup current registry file to a temp folder
        Install the Company Portal APPXBUNDLE File.
        Use the DSREG commandline tool to determine if computer has received a Primary Refresh Token from AAD.
            Also determine if device is hybrid joined.
            Also determine if user's profile is an Azure AD user.
        Update group policy and log associated failure.
            (TBD) Add registry key to enable diagnostic logging for Group Policy.
            Send the contents of that file home.
        Attempt to determine currently enrolled MDM provider.
            If necessary, remove currently enrolled MDM provider.
                Remove registry values and uninstall agent if one is present.
            Send home the current MDM provider if found.
        Restore registry file in case of error.
    The script will log all actions.
    The script will call home when the script has started, when it has ended, and send debugging information.

    The script has no parameter options.

.EXAMPLE
    .\CITIntuneDeploymentInfo.ps1
.EXAMPLE
    powershell.exe -Command "& { & '.\CITIntuneDeploymentInfo.ps1'; Exit }"
.EXAMPLE
    Execute-Process -Path "$($envWinDir)\System32\WindowsPowerShell\v1.0\powershell.exe" -Parameters "-WindowsStyle Hidden -File `"$($DirFiles)\CITIntuneDeploymentInfo.ps1`""
.NOTES
	Please feel free to use any source code within this script.

    #LICENSE
    MIT License

    Copyright (c) 2021 Emmanuel Cardenas

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    RESERACH, TO BE REMOVED:
    Registry Hive: https://superuser.com/questions/111311/where-are-registry-files-stored-in-windows
    Manually re-enroll: https://www.maximerastello.com/manually-re-enroll-a-co-managed-or-hybrid-azure-ad-join-windows-10-pc-to-microsoft-intune-without-loosing-current-configuration/
    Troubleshooting Hybrid Join: https://docs.microsoft.com/en-us/azure/active-directory/devices/faq#:~:text=Open%20the%20command%20prompt%20as,device%20again%20with%20Azure%20AD.

.LINK
	Conact Manny for more information: manny@recursion.com
#>

try
{
	## Set the script execution policy for this process
	Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' }
	Catch { }
	
	add-type -AssemblyName System
	
	##*===============================================
	##* VARIABLE DECLARATION
	##*===============================================
	#region Variables
	## Variables: Environment
	$VerbosePreference = "Continue"
	If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation }
	Else { $InvocationInfo = $MyInvocation }
	[string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent
	
	[string]$toolkitMainFunctions = $(Split-Path -Path $($scriptDirectory) -Parent) + "\AppDeployToolkit\AppDeployToolkitMain.ps1"
	
	## Dot source the required App Deploy Toolkit Functions
	Try
	{
		[string]$moduleIntuneFunctions = "$scriptDirectory\CITIntuneFunctions.ps1"
		If (-not (Test-Path -LiteralPath $moduleIntuneFunctions -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$moduleIntuneFunctions]." }
		. $moduleIntuneFunctions
		
		If (-not (Test-Path -LiteralPath $toolkitMainFunctions -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$toolkitMainFunctions]." }
		. $toolkitMainFunctions
		
		$gsheetFunctionsLoaded = "Loaded [$moduleIntuneFunctions] module."
	}
	Catch
	{
		Write-Error -Message "Module [$moduleIntuneFunctions] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		$gsheetFunctionsLoaded = "Failed to load [$moduleIntuneFunctions] module."
	}
	
	## Variables: Registry
	$registryKeyArray = @(
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\'; EXPORT = 'EnrollmentsKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Status\'; EXPORT = 'EnrollmentsStatusKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\'; EXPORT = 'ERMTrackedKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\'; EXPORT = 'PMAdmxInstalledKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Providers\'; EXPORT = 'PMProvidersKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\'; EXPORT = 'ProvisioningOMADMAccountsKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\'; EXPORT = 'ProvisioningOMADMLoggerKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\'; EXPORT = 'ProvisioningOMADMSessionsKey.reg' }
		[PSCustomObject]@{ KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; EXPORT = 'CurrentVersionDiagnosticsKey.reg' }
	)
	$regExitStatus = ""
	[string]$regDateFolder = "IntuneEnrollmentRegistryBackup" + (Get-Date).ToString("dd-MM-yyyy")
	[string]$placeholderDateFolder = $Env:Temp + "\" + $regDateFolder
	
	## Variables: Company Portal
	$getPackagePortal = Get-AppxPackage -AllUsers | Where-Object -Property "Name" -EQ "Microsoft.CompanyPortal"
	
	## Variables: DSREGCMD
	$dsregStatus = dsregcmd.exe /status
	
	## Variables: MDM Provider
	[string]$guidDiscovery = ''
	[string]$exitRemovalVerbose = ''
	$currentProviderArray = ''
	[string]$currentProviderGUID = ''
	$mdmRegistryKeyArray = @(
		'HKLM:\SOFTWARE\Microsoft\Enrollments\'
		'HKLM:\SOFTWARE\Microsoft\Enrollments\Status\'
		'HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\'
		'HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\'
		'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\'
		'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\'
		'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\'
		'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\'
	)
	[boolean]$mdmRegistryRemovalTracker = $false
	
	## Variables: Group Policy
	$gpoExitStatus = ''
	[bool]$gpoAdvancedLogging = $false
	[Int32]$gpoDebugTest = 0
	
	## Variables: Google Sheets
	[string]$moduleNeeded = "UMN-Google"
	[string]$moduleTrack = $null
	$scope = $null
	$certPath = $null
	$saCertGCP = $null
	$iss = $null
	$certPswd = $null
	$accessToken = $null
	$SpreadsheetID = $null
	$sheetsArray = New-Object System.Collections.ArrayList($null)
	$sheetName = $null
	$gapiCertificate = $null
	$gapiCertPath = $null
	#$sheetsArray.Add(@("Computer Name", "Date Time", "Script Version". "Script Deploy Date", "Innvocation Path", "Functions Loaded", "Restore Point Enabled", "Checkpoint Computer". "Registry Backup Path", "Backup Results", "Company Portal Install", "DSREG Device State", "DSREG SSO State", "DSREG Ngc Prereq", "MDM Enrollment", "MDM Action", "MDM Registry Keys", "MDM Agent", "Group Policy Update", "GPSVC Log Action", "GPSVC Log", "Enrollment Called", "Errors", "Finally", "Transcript Log")) | Out-Null
	
	## Google Sheet Column Data
	[string]$gsheetRegistryBackupPath = $null
	$gsheetRegistryBackupResults = @()
	[string]$gsheetCompanyInstall = $null
	[string]$gsheetDsregDevice = $null
	[string]$gsheetDsregSSOState = $null
	[string]$gsheetDsregNgcPreq = $null
	[string]$gsheetMDMEnrollment = $null
	[string]$gsheetMDMAction = $null
	$gsheetMDMRegistryKeys = @()
	[string]$gsheetMDMAgent = $null
	[string]$gsheetGroupPolicy = $null
	$gsheetGpsvcLogAction = @()
	$gsheetGpsvcLogContents = $null
	[string]$gsheetEnrollmentCalled = $null
	$gsheetErrors = @()
	$gsheetFinally = @()
	$gsheetTranscriptLog = $null
	
	## Variables: Logging
	$dateStamp = get-date -Format yyyyMMddTHHmmss
	[string]$logFile = '{0}-{1}-intune-enrollment.log' -f $env:computername, $dateStamp
	[string]$logPath = "$env:windir\Logs\intune-enrollment\$logFile"
	[string]$logPathGSheet = "$env:windir\Logs\intune-enrollment\GSheet - $logFile"
	$transcriptLogContents = ''
	
	## Variables: Exit Code
	[int32]$mainExitCode = 0
	
	## Variables: Script
	[string]$scriptFriendlyName = 'Intune Enrollment Helper'
	[version]$deployAppScriptVersion = [version]'0.0.1'
	[string]$deployAppScriptDate = '06/02/2022'
	
	#endregion
	
	# Start transcript logging
	Start-Transcript -Path $logPath -Append
	
	##*===============================================
	##* END VARIABLE DECLARATION
	##*===============================================
	
	##*===============================================
	##* Backup Registry Files
	##*===============================================
	#region Registry
	## Attempt to verify if System Restore point is enabled for the system.
	try
	{
		Write-Verbose -Message "Attempting to enable System Restore Point."
		
		Enable-ComputerRestore -Drive "C:\"
		
	}
	catch
	{
		Write-Error -Message "Failed to enable system restore: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
	}
	
	## Create a restore point (NOTE: only one can be created in a 24 hour time frame)
	try
	{
		Write-Verbose -Message "Attempting to create a System Restore Point."
		
		Checkpoint-Computer -Description "Intune Deployment Script modification of system"
		
	}
	catch
	{
		Write-Error -Message "Failed to create a system restore point: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
	}
	
	do
	{
		<#
			For more information on the try, catch and finally keywords, see:
				Get-Help about_try_catch_finally
		#>
		
		# Try one or more commands
		try
		{
			
			switch ($registryFolderErrorChanges)
			{
				0 {
					Write-Verbose -Message "No change to registry folder."
				}
				1 {
					Write-Verbose -Message "Changing folder to the common program files folder."
					
					$placeholderDateFolder = $Env:CommonProgramFiles + "\" + $regDateFolder
				}
				2 {
					Write-Verbose -Message "Changing folder to location invocation path."
					
					$placeholderDateFolder = $scriptDirectory + "\" + $regDateFolder
				}
				default {
					Write-Verbose -Message "Default switch option achieved for registry folder backup. Not a desired result."
					
					$placeholderDateFolder = $Env:Temp + "\" + $regDateFolder
				}
			}
			
			## Backup the hive folders that will be modified in this script.
			
			if (Test-Path -Path $placeholderDateFolder)
			{
				Write-Verbose -Message "Found the temp folder to copy the hive folder into. [$placeholderDateFolder]"
			}
			else
			{
				try
				{
					switch ($registryFolderErrorChanges)
					{
						0 {
							Write-Verbose -Message "Creating temp folder $placeholderDateFolder"
							
							New-Item -Path $Env:Temp -Name $regDateFolder -ItemType "directory"
						}
						1 {
							Write-Verbose -Message "Creating temp folder $placeholderDateFolder"
							New-Item -Path $Env:CommonProgramFiles -Name $regDateFolder -ItemType "directory"
						}
						2 {
							Write-Verbose -Message "Creating temp folder $placeholderDateFolder"
							New-Item -Path $scriptDirectory -Name $regDateFolder -ItemType "directory"
						}
						default {
							Write-Verbose -Message "Creating temp folder $placeholderDateFolder"
							New-Item -Path $Env:Temp -Name $regDateFolder -ItemType "directory"
						}
					}
				}
				catch
				{
					Write-Error -Message "Failed to create the registry backup folder: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
				}
			}
			
		<#
			For more information on the try, catch and finally keywords, see:
				Get-Help about_try_catch_finally
		#>
			
			# Try one or more commands
			try
			{
				Write-Verbose -Message "Setting location to the registry backup folder: $placeholderDateFolder"
				
				Start-Sleep -Seconds 10
				Set-Location -Path $placeholderDateFolder
				
				if ($?)
				{
					Write-Verbose -Message "Setting loop condition to true as set location didn't error our."
					$dedicatedToJohn = $true
				}
				else
				{
					Write-Verbose -Message "Setting loop condition to false as set location errored out."
					$dedicatedToJohn = $false
					throw $error[0].Exception
				}
				
			}
			# Catch all other exceptions thrown by one of those commands
			catch
			{
				Write-Error -Message "Failed to set location to the registry backup folder: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
				
				## Set do until condition to false, keep it looping.
				$dedicatedToJohn = $false
				
				Throw "Failed to set the location to the backup registry location: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
			}
		}
		# Catch specific types of exceptions thrown by one of those commands
		catch [System.Exception] {
			Write-Error -Message "Failed during the registry backup phase: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
			$dedicatedToJohn = $false
		}
		# Catch all other exceptions thrown by one of those commands
		catch
		{
			Write-Error -Message "Failed during the registry backup phase: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
			$dedicatedToJohn = $false
		}
		
		if ($registryFolderErrorChanges -eq 3)
		{
			Throw "Failed to create and write to a registry backup location (John's fault!): `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
		}
		
		$registryFolderErrorChanges++
		$gsheetRegistryBackupPath = $placeholderDateFolder
	}
	until ($dedicatedToJohn)
	
	Write-Verbose -Message "Attempting to backup necessary registry key hives."
	$registryKeyArray | ForEach-Object {
		
		Write-Verbose -Message "Testing to see if $($_.EXPORT) registry export file already exists."
		
		if (Test-Path -Path "$placeholderDateFolder\$($_.EXPORT)")
		{
			Write-Verbose -Message "Exported key [$($_.EXPORT)] already exists, skipping export."
		}
		elseif (-Not (Test-Path -Path "$placeholderDateFolder\$($_.EXPORT)"))
		{
			Write-Verbose -Message "Exported key [$($_.EXPORT)] doesn't exist, moving onto reg export."
			
			try
			{
				## Use the REG command to export and catch the return code.
				$regExitStatus = Invoke-Command { REG EXPORT "$($_.KEY)" $($_.EXPORT) }
			}
			catch
			{
				$gsheetRegistryBackupResults += "Failed to export the current registry key  `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage) `n"
				Write-Error -Message "Failed to export the current registry key  `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction Continue
			}
			
			if ($regExitStatus -Match "successfully")
			{
				Write-Verbose -Message "Successfully exported registry hive: $($_.KEY)"
				$gsheetRegistryBackupResults += "Successfully exported registry hive: $($_.KEY)"
			}
			elseif (-Not ($regExitStatus -Match "successfully"))
			{
				Write-Error -Message "Failed to export registry hive: $($_.KEY)" -ErrorAction 'Continue'
				$gsheetRegistryBackupResults += "Failed to export registry hive: $($_.KEY)"
			}
			else
			{
				Write-Error -Message "Failed atempt to export registry hive: $($_.KEY). Either due to an internal error or unknown error." -ErrorAction 'Continue'
				$gsheetRegistryBackupResults += "Failed atempt to export registry hive: $($_.KEY). Either due to an internal error or unknown error."
			}
		}
		else
		{
			Write-Error -Message "Failed to determine if registry hive has already been exported. No action was taken." -ErrorAction 'Continue'
			$gsheetRegistryBackupResults += "Failed to determine if registry hive has already been exported. No action was taken."
		}
	}
	
	Write-Verbose -Message "Restoring previous location: $scriptDirectory"
	Set-Location -Path $scriptDirectory
	#endregion Registry
	##*===============================================
	##* END REGISTRY BACKUP
	##*===============================================
	
	##*===============================================
	##* Install the Company Portal
	##*===============================================
	#region Company Portal
	## Determine if it's installed
	if ($getPackagePortal.Name -Match "Microsoft.CompanyPortal")
	{
		Write-Verbose -Message "The Company Portal package is already installed."
		$gsheetCompanyInstall = "The Company Portal package is already installed."
	}
	elseif (-Not ($getPackagePortal.Name -Match "Microsoft.CompanyPortal"))
	{
		Write-Verbose -Message "The Company Portal package is not installed, preparing to install."
		<#
			For more information on the try, catch and finally keywords, see:
				Get-Help about_try_catch_finally
		#>
		
		# Try one or more commands
		try {
			Add-AppxPackage -Path "$scriptDirectory\Microsoft.CompanyPortal_2021.1209.812.0_neutral___8wekyb3d8bbwe.AppxBundle"
			
			$gsheetCompanyInstall = "Installed the Company Portal."
		}
		# Catch all other exceptions thrown by one of those commands
		catch
		{
			Write-Error -Message "Failed to install the Company Portal: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		}
		## Call Add-AppxPackage cmdlet to install the AppxBundle
	}
	else
	{
		Write-Error -Message "Unabled to determine if the Company Portal needs to be installed." -ErrorAction Continue
		$gsheetCompanyInstall = "Unabled to determine if the Company Portal needs to be installed."
	}
	#endregion Company Portal
	##*===============================================
	##* END COMPANY PORTAL
	##*===============================================
	
	##*===============================================
	##* Check DSREG commandline tool
	##*===============================================
	#region DSREG
	
	## Check the Device State
	Write-Verbose -Message "Checking the Device State."
	if (($dsregStatus -Match "AzureAdJoined : YES") -and ($dsregStatus -Match "DomainJoined : YES"))
	{
		Write-Verbose -Message "Device $Env:computername is Hybrid Joined"
		$gsheetDsregDevice = "Device $Env:computername is Hybrid Joined"
	}
	elseif (($dsregStatus -Match "AzureAdJoined : NO") -and ($dsregStatus -Match "DomainJoined : YES"))
	{
		Write-Error -Message "Device $Env:computername is joined to the domain, but not joined to ADD. In the current state, a hybrid join is not in effect." -ErrorAction 'Continue'
		
		Write-Verbose -Message "Attempting to re-register the device again with Azure AD. User will be advised to logout and back in."
		
		$gsheetDsregDevice = "Device $Env:computername is joined to the domain, but not joined to ADD. In the current state, a hybrid join is not in effect."
		
		dsregcmd.exe /debug /leave
		
		## A pop up is required to discuss with user about the script, the error, and why they need to logout and back in asap.
	}
	elseif (($dsregStatus -Match "AzureAdJoined : YES") -and ($dsregStatus -Match "DomainJoined : NO"))
	{
		Write-Error -Message "Hmm, this one is a weird one for our environment. Device is AAD joined, but not joined to on-prem AD."
		
		$gsheetDsregDevice = "Hmm, this one is a weird one for our environment. Device is AAD joined, but not joined to on-prem AD."
	}
	elseif (($dsregStatus -Match "AzureAdJoined : NO") -and ($dsregStatus -Match "DomainJoined : NO"))
	{
		Write-Error -Message "Device is not ADD joined nor joined to the on-prem AD."
		
		$gsheetDsregDevice = "Device is not ADD joined nor joined to the on-prem AD."
	}
	else
	{
		Write-Error -Message "Device state evaluation completed without a successful evaluation or an error occured." -ErrorAction 'Continue'
		
		$gsheetDsregDevice = "Device state evaluation completed without a successful evaluation or an error occured."
	}
	
	## Check the SSO State
	
	###### For this to work, dsregcmd needs to be run as the currently signed in user. Otherwise, it'll run as System.
	if ($dsregStatus -Match "AzureAdPrt : YES")
	{
		Write-Verbose -Message "Device has received a Primary Refresh Token for the current user."
		$gsheetDsregSSOState = "Device has received a Primary Refresh Token for the current user."
	}
	elseif ($dsregStatus -Match "AzureAdPrt : NO")
	{
		Write-Error -Message "A Primary Refresh Token was not found for the current user."
		$gsheetDsregSSOState = "A Primary Refresh Token was not found for the current user."
		
		## Throw up a popup instructing the user to logout and back in.
	}
	else
	{
		Write-Error -Message "SSO state evaluation completed without a successful evaluation or an error occured." -ErrorAction 'Continue'
		$gsheetDsregSSOState = "SSO state evaluation completed without a successful evaluation or an error occured."
	}
	
	## Check the Ngc Prerequisite Check
	
	###### For this to work, dsregcmd needs to be run as the currently signed in user. Otherwise, it'll run as System.
	if ($dsregStatus -Match "IsUserAzureAD : YES")
	{
		Write-Verbose -Message "The current user's AAD identity was successfully retrieved and integrated with their profile."
		$gsheetDsregNgcPreq = "The current user's AAD identity was successfully retrieved and integrated with their profile."
	}
	elseif ($dsregStatus -Match "IsUserAzureAD : NO")
	{
		Write-Error -Message "No AAD identify was found for the current user."
		$gsheetDsregNgcPreq = "No AAD identify was found for the current user."
	}
	else
	{
		Write-Error -Message "Ngc Prerequisite Check evaluation completed without a successful evaluation or an error occured." -ErrorAction 'Continue'
		$gsheetDsregNgcPreq = "Ngc Prerequisite Check evaluation completed without a successful evaluation or an error occured."
	}
	
	#endregion DSREG
	##*===============================================
	##* END DSREG COMMANDLINE
	##*===============================================
	
	##*===============================================
	##* MDM Provider Check and Rectify
	##*===============================================
	#region MDM check
	
	##Attempt to determine currently enrolled MDM provider
	##If a third-party provider, attempt to remove MDM provider
	
	Write-Verbose -Message "Checking the currently enrolled MDM provider."
	
	Write-Verbose -Message "Attempting to retrieve enrollment: $($(Get-MDMEnrollmentStatus).EnrollmentTypeText) `nEnrollment ID: $($(Get-MDMEnrollmentStatus).PSChildName) `nProviderID: $($(Get-MDMEnrollmentStatus).ProviderID)"
	
	$gsheetMDMEnrollment = "Attempting to retrieve enrollment: $($(Get-MDMEnrollmentStatus).EnrollmentTypeText) `nEnrollment ID: $($(Get-MDMEnrollmentStatus).PSChildName) `nProviderID: $($(Get-MDMEnrollmentStatus).ProviderID)"
	
	## Store enrollment information in variable
	$currentProviderArray = Get-MDMEnrollmentStatus
	
	$currentProviderGUID = $currentProviderArray.PSChildName
	
	Write-Verbose -Message "Attempting to verify MDM provider whether it matches Meraki."
	
	if ($currentProviderArray.ProviderID -eq "MerakiMdmServer")
	{
		Write-Verbose -Message "Current MDM provider is Meraki. `n`nMoving to unenroll"
		
		$gsheetMDMAction = "Current MDM provider is Meraki. `n`nMoving to unenroll"
		
		## Attempt to unenroll Mearki through Registry keys.
		
		## First Step, delete all stale tasks in Task Scheduler
		Write-Verbose -Message "Removing the Enterprise Management tasks from Task Scheduler. `nRemoving folder: $Env:windir\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$currentProviderGUID"
		
		$gsheetMDMRegistryKeys += "Removing the Enterprise Management tasks from Task Scheduler. `nRemoving folder: $Env:windir\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$currentProviderGUID"
		
		try
		{
			Remove-Item -Path "$Env:windir\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$currentProviderGUID" -Recurse
		}
		catch
		{
			Write-Error -Message "Failed to remove task folder [$Env:windir\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$currentProviderGUID]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
			$gsheetMDMRegistryKeys += "Failed to remove task folder [$Env:windir\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$currentProviderGUID]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
		}
		
		## Second Step, delete all previous enrollment registry keys
		Write-Verbose -Message "Remove the MDM Provider Registry keys."
		
		[string]$mdmKeyFullPathGuid = ''
		
		foreach ($mdmKey in $mdmRegistryKeyArray)
		{
			try
			{
				$mdmKeyFullPathGuid = $mdmKey + $currentProviderGUID
				Write-Verbose -Message "Attempting to remove the following registry key hive: $mdmKeyFullPathGuid"
				$gsheetMDMRegistryKeys += "Attempting to remove the following registry key hive: $mdmKeyFullPathGuid"
				
				if ($Null -ne $(Get-ItemProperty "$mdmKeyFullPathGuid"))
				{
					Write-Verbose -Message "Found the registry key [$mdmKeyFullPathGuid]. Attempting to remove hive."
					$gsheetMDMRegistryKeys += "Found the registry key [$mdmKeyFullPathGuid]. Attempting to remove hive."
					
					try
					{
						Remove-Item -Path "$mdmKeyFullPathGuid" -Recurse
					}
					catch
					{
						Write-Error -Message "Failed to remove registry key [$mdmKeyFullPathGuid]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
						$gsheetMDMRegistryKeys += "Failed to remove registry key [$mdmKeyFullPathGuid]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
					}
				}
				elseif ($Null -eq $(Get-ItemProperty "$mdmKeyFullPathGuid"))
				{
					Write-Verbose -Message "Could not detect the registry key [$mdmKeyFullPathGuid]."
					$gsheetMDMRegistryKeys += "Could not detect the registry key [$mdmKeyFullPathGuid]."
					
				}
				else
				{
					Write-Error -Message "Failed to find and delete registry value of $mdmKeyFullPathGuid" -ErrorAction 'Continue'
					$gsheetMDMRegistryKeys += "Failed to find and delete registry value of $mdmKeyFullPathGuid"
				}
			}
			catch
			{
				Write-Error -Message "Failed attempting to remove MDM keys [$mdmKeyFullPathGuid]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
				
				Write-Verbose -Message "Setting MDM registry tracker to true since the registry was modified."
				# Set MDM registry tracker to true since MDM enrollment through the registry was attempted but not successful.
				$mdmRegistryRemovalTracker = $true
				
				$gsheetMDMRegistryKeys += "Failed to remove the MDM key: [$mdmKeyFullPathGuid]. `nThis may be an issue with how the key was retrieved, the commandlet not being able to remove the key, or invalid configuration. `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
				
				Throw "Failed to remove the MDM key: [$mdmKeyFullPathGuid]. `nThis may be an issue with how the key was retrieved, the commandlet not being able to remove the key, or invalid configuration. `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
			}
		}
		
		Write-Verbose -Message "Setting MDM registry tracker to true since the registry was modified."
		# Set MDM registry tracker to true since MDM enrollment through the registry was successful.
		$mdmRegistryRemovalTracker = $true
	}
	elseif ($currentProviderArray.ProviderID -eq "MS DM Server")
	{
		Write-Verbose -Message "Current MDM provider is Microsoft Intune! Yay!"
		$gsheetMDMAction = "Current MDM provider is Microsoft Intune! Yay!"
	}
	else
	{
		Write-Error -Message "The current MDM provider isn't in the current list of MDM providers we use. This is not the desired effect. Please check on this."
		$gsheetMDMAction = "The current MDM provider isn't in the current list of MDM providers we use. This is not the desired effect. Please check on this."
	}
	
	## Determine if MDM agent is installed.
	Write-Verbose -Message "Determine if Meraki Agent is installed."
	$guidDiscovery = Get-MSIGUID -msiName "Meraki Systems Manager Agent"
	
	if ($guidDiscovery -ne $true)
	{
		Write-Verbose -Message "Found the Meraki agent, attempting to uninstall."
		
		$gsheetMDMAgent = "Found the Meraki agent, attempting to uninstall."
		
		try
		{
			$exitRemovalVerbose = Remove-MSIPackage -guid $guidDiscovery
			Write-Verbose -Message "$(Get-LogDate) Remove-MSIPackage was executed with status [$exitRemovalVerbose]"
			$gsheetMDMAgent = "$(Get-LogDate) Remove-MSIPackage was executed with status [$exitRemovalVerbose]"
		}
		catch
		{
			Write-Error -Message "Failed to remove application [$(Get-GUIDName -identNumber $guidDiscovery)]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
			$gsheetMDMAgent = "Failed to remove application [$(Get-GUIDName -identNumber $guidDiscovery)]: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
		}
	}
	elseif ($guidDiscovery -eq $true)
	{
		Write-Verbose -Message "Did not find the Meraki agent installed."
		$gsheetMDMAgent = "Did not find the Meraki agent installed."
	}
	else
	{
		Write-Error -Message "Failed to find the Meraki agent package installed. It may or may not be installed." -ErrorAction 'Continue'
		$gsheetMDMAgent = "Failed to find the Meraki agent package installed. It may or may not be installed."
	}
	
	#endregion
	##*===============================================
	##* END MDM PROVIDER
	##*===============================================
	
	
	##*===============================================
	##* ATTEMPT TO UPDATE GROUP POLICY
	##*===============================================
	#region Group Policy
	
	##Attempt to update group policy
	
	if ((Test-Connection "41-rp-ad02.corp.internal" -Count 1 -Quiet) -OR (Test-Connection 172.16.2.3 -Count 1 -Quiet))
	{
		Write-Verbose -Message "Verified connection to AD02. Device can communicate to the onsite network."
		
		try
		{
			Write-Verbose -Message "Invoking a Group Policy update for both Computer and User policies."
			$gpoExitStatus = gpupdate.exe /force
			
			$gpoExitStatus
		}
		catch
		{
			Write-Error -Message "Failed to update group policy: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		}
		
		## If the GPO update failed in any of its components, start advanced troubleshooting.
		if ($gpoExitStatus -Match "failed")
		{
			Write-Verbose -Message "Detected an error while group policy was updating."
			
			$gsheetGroupPolicy = "Detected an error while group policy was updating."
			
			try
			{
				Write-Verbose -Message "Attempting to enable Group Policy Advanced Troubleshooting..."
				
				$gsheetGpsvcLogAction += "Attempting to enable Group Policy Advanced Troubleshooting..."
				
				if ($(Test-RegistryValue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics' -Value 'GPSvcDebugLevel'))
				{
					Write-Verbose -Message "Found the registry key [GPSvcDebugLevel]. Attempting to verify the value."
					
					$gsheetGpsvcLogAction += "Found the registry key [GPSvcDebugLevel]. Attempting to verify the value."
					
					$gpoDebugTest = Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" | Select-Object -ExpandProperty "GPSvcDebugLevel"
					if ($gpoDebugTest -eq 196610)
					{
						Write-Verbose -Message "Value of the registry key is correct [$gpoDebugTest]."
						
						$gsheetGpsvcLogAction += "Value of the registry key is correct [$gpoDebugTest]."
					}
					elseif ($gpoDebugTest -ne 196610)
					{
						Write-Verbose -Message "Value of the registry key is not correct [$gpoDebugTest]. Attempting to correct value."
						
						$gsheetGpsvcLogAction +=
						try
						{
							Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" -Name "GPSvcDebugLevel" -Value 196610
							
							Write-Verbose -Message "Set the value of GPSvcDebugLevel to 196610."
							
							$gsheetGpsvcLogAction += "Set the value of GPSvcDebugLevel to 196610."
						}
						catch
						{
							Write-Error -Message "Failed to set registry value of GPSvcDebugLevel: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
							
							$gsheetGpsvcLogAction += "Failed to set registry value of GPSvcDebugLevel: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
						}
					}
				}
				elseif (-Not $(Test-RegistryValue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics' -Value 'GPSvcDebugLevel'))
				{
					Write-Verbose -Message "Could not detect the registry key [GPSvcDebugLevel]. Attempting to create the key."
					
					$gsheetGpsvcLogAction += "Could not detect the registry key [GPSvcDebugLevel]. Attempting to create the key."
					
					try
					{
						New-Item -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\' -Name 'Diagnostics'
						New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics' -Name 'GPSvcDebugLevel' -Value 196610 -PropertyType DWord
						
						Write-Verbose -Message "Created registry key and set value. Value has a set type as DWord."
						
						$gsheetGpsvcLogAction += "Created registry key and set value. Value has a set type as DWord."
						Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics"
					}
					catch
					{
						Write-Error -Message "Failed to set registry value of GPSvcDebugLevel: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
						
						$gsheetGpsvcLogAction += "Failed to set registry value of GPSvcDebugLevel: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
					}
				}
				else
				{
					Write-Error -Message "Failed to find and/or set registry value of GPSvcDebugLevel." -ErrorAction 'Continue'
					
					$gsheetGpsvcLogAction += "Failed to find and/or set registry value of GPSvcDebugLevel."
				}
				
				Start-Sleep -Seconds 2
				
				try
				{
					Write-Verbose -Message "Invoking a Group Policy update for both Computer and User policies."
					
					$gsheetGpsvcLogAction += "Invoking a Group Policy update for both Computer and User policies."
					$gpoExitStatus = gpupdate.exe /force
					
					$gpoExitStatus
				}
				catch
				{
					Write-Error -Message "Failed to update group policy: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
					
					$gsheetGpsvcLogAction += "Failed to update group policy: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
				}
				
				Write-Verbose -Message "Setting tracking variable to True since debugging registry key was enabled."
				$gpoAdvancedLogging = $true
			}
			catch
			{
				Write-Error -Message "Failed attempting to enable Group Policy Advanced Troubleshooting: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
				
				$gsheetGpsvcLogAction += "Failed attempting to enable Group Policy Advanced Troubleshooting: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
			}
		}
		elseif (-Not ($gpoExitStatus -Match "failed")) {
			Write-Verbose -Message "Group Policy updated successfully!"
			
			$gsheetGroupPolicy = "Group Policy updated successfully!"
		}
	}
	else
	{
		Write-Error -Message "Unable to detect a connection to the on-site network or an error occured while testing the connection."
		
		$gsheetGroupPolicy = "Unable to detect a connection to the on-site network or an error occured while testing the connection."
	}
	
	#endregion
	##*===============================================
	##* END GPO UPDATE
	##*===============================================
	
	##*===============================================
	##* Restart the Enrollment Process
	##*===============================================
	#region Restart Enrollment
	
	## Verify PSTools are in the script directory
	if (Test-Path -Path "$scriptDirectory\PSTools\PsExec.exe")
	{
		Write-Verbose -Message "Found the PSTools folder. Attempting to use PSEXEC to start the enrollment process."
		
		try
		{
			Set-Location "$scriptDirectory\PSTools\" -Verbose
			
			.\PsExec.exe /accepteula /i /s cmd /c "%windir%\system32\deviceenroller.exe /c /AutoEnrollMDM"
			
			$gsheetEnrollmentCalled = "Called the device enroller cmd line tool to trigger an auto enroll."
		}
		catch
		{
			Write-Error -Message "Failed to create the registry backup folder: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
			
			$gsheetEnrollmentCalled = "Failed to create the registry backup folder: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
		}
	}
	elseif ((Test-Path -Path "$scriptDirectory\PSTools\PsExec.exe") -eq $false)
	{
		Write-Error -Message "Wasn't able to find or access the PSTools folder."
		
		$gsheetEnrollmentCalled = "Wasn't able to find or access the PSTools folder."
	}
	else
	{
		Write-Error -Message "Failed with an unknown error attempting to access the PSTools folder." -ErrorAction 'Continue'
		
		$gsheetEnrollmentCalled = "Failed with an unknown error attempting to access the PSTools folder."
	}
	
	#endregion
	##*===============================================
	##* END RESTART ENROLLMENT PROCESS
	##*===============================================
	
	## Show restart prompt if script made it to the end
	Show-InstallationRestartPrompt -NoCountdown
}
catch
{
	Write-Error -Message "Script caught an execution in the main process: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
	
	$gsheetErrors += "Script caught an execution in the main process: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
	New-DiagBox -msgTitle "Error!" -msgButton OK -msgBody "An error occured while trying to enroll your device ($Env:COMPUTERNAME). Please take a screenshot of this screen and send to Manny on the IT Team. Thanks! `nError:($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -msgIcon 'Stop'
	
	Write-Verbose -Message "An uncaught exception occured, attempting to verify if registry was modified and rollback if necessary..."
	
	if ($mdmRegistryRemovalTracker)
	{
		Write-Verbose -Message "Detected the registry was modified in an attempt to remove MDM registry values to unenroll. `nAttempting to rollback."
		$gsheetErrors += "Detected the registry was modified in an attempt to remove MDM registry values to unenroll. `nAttempting to rollback."
		
		Write-Verbose -Message "Setting location to the registry backup folder: $placeholderDateFolder"
		Set-Location -Path $placeholderDateFolder
		
		Write-Verbose -Message "Attempting to import the registry key hives that were backed up."
		$registryKeyArray | ForEach-Object {
			
			Write-Verbose -Message "Testing to see if $($_.EXPORT) registry export file already exists."
			
			if (Test-Path -Path "$placeholderDateFolder\$($_.EXPORT)")
			{
				Write-Verbose -Message "Exported key [$($_.EXPORT)] exists, attempting to import."
				
				try
				{
					## Use the REG command to import and catch the return code.
					$regExitStatus = Invoke-Command { REG IMPORT $($_.EXPORT) }
				}
				catch
				{
					Write-Error -Message "Failed to import the current registry key  `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction Continue
					
					$gsheetErrors += "Failed to import the current registry key  `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
				}
				
				if ($regExitStatus -Match "successfully")
				{
					Write-Verbose -Message "Successfully import registry hive: $($_.KEY)"
					
					$gsheetErrors += "Successfully import registry hive: $($_.KEY)"
				}
				elseif (-Not ($regExitStatus -Match "successfully"))
				{
					Write-Error -Message "Failed to import registry hive: $($_.KEY)" -ErrorAction 'Continue'
					
					$gsheetErrors += "Failed to import registry hive: $($_.KEY)"
				}
				else
				{
					Write-Error -Message "Failed atempt to import registry hive: $($_.KEY). Either due to an internal error or unknown error." -ErrorAction 'Continue'
					
					$gsheetErrors += "Failed atempt to import registry hive: $($_.KEY). Either due to an internal error or unknown error."
				}
			}
			elseif (-Not (Test-Path -Path "$placeholderDateFolder\$($_.EXPORT)"))
			{
				Write-Verbose -Message "Exported key [$($_.EXPORT)] doesn't exist, ignoring this key."
				
				$gsheetErrors += "Exported key [$($_.EXPORT)] doesn't exist, ignoring this key."
			}
			else
			{
				Write-Error -Message "Failed to import the backed up registry hive. No action was taken." -ErrorAction 'Continue'
				
				$gsheetErrors += "Failed to import the backed up registry hive. No action was taken."
			}
		}
		
		Write-Verbose -Message "Restoring previous location: $scriptDirectory"
		Set-Location -Path $scriptDirectory
	}
	elseif (-Not ($mdmRegistryRemovalTracker))
	{
		Write-Verbose -Message "Detected the registry was not modified to remove the MDM keys. Skipping rollback."
		
		$gsheetErrors += "Detected the registry was not modified to remove the MDM keys. Skipping rollback."
	}
	else
	{
		Write-Error -Message "Unable to determine if the registry was modified to attempt removal of the MDM registry keys."
		
		$gsheetErrors += "Unable to determine if the registry was modified to attempt removal of the MDM registry keys."
	}
}
finally
{
	#Roll back any temporary changes.
	Set-Location $scriptDirectory -Verbose
	
	## Remove Advanced GPO Debugging Reg Key (If necessary)
	if (($gpoAdvancedLogging) -OR $(Test-Path -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics'))
	{
		Write-Verbose -Message "Detected advanced group policy logging was enabled. Attempting to reverse and delete file."
		$gsheetFinally += "Detected advanced group policy logging was enabled. Attempting to reverse and delete file."
		
		try
		{
			Write-Verbose -Message "Attempting to disable Group Policy Advanced Troubleshooting..."
			
			if ($(Test-Path -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics'))
			{
				Write-Verbose -Message "Detected the Group Policy Advanced Troubleshooting registry key. Attempting to remove the key. [HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics]"
				$gsheetFinally += "Detected the Group Policy Advanced Troubleshooting registry key. Attempting to remove the key. [HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics]"
				
				try
				{
					Remove-Item -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics' -Recurse -Force -ErrorAction Continue
					
					Write-Verbose -Message "Removed registry key HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics."
					$gsheetFinally += "Removed registry key HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics."
				}
				catch
				{
					Write-Error -Message "Failed to registry key HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
					$gsheetFinally += "Failed to registry key HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
				}
			}
			elseif (-Not $(Test-Path -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics'))
			{
				Write-Verbose -Message "Could not detect the registry key [HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics]."
				$gsheetFinally += "Could not detect the registry key [HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics]."
			}
			else
			{
				Write-Error -Message "Failed to find registry key: HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" -ErrorAction 'Continue'
				$gsheetFinally += "Failed to find registry key: HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics"
			}
		}
		catch
		{
			Write-Error -Message "Failed attempting to disable Group Policy Advanced Troubleshooting: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
			$gsheetFinally += "Failed attempting to disable Group Policy Advanced Troubleshooting: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)"
		}
	}
	
	# Stop logging
	Stop-Transcript
	
	# Start transcript logging
	Start-Transcript -Path $logPathGSheet -Append
	
	##*===============================================
	##* Send to GSheets
	##*===============================================
	#region Send to GSheets
	
	# Install Powershell wrapper to interact with Google API
	Write-Verbose -Message "Attempting to download and install the $moduleNeeded module from PS App Gallery."
	
	$gsheetFinally += "Attempting to download and install the $moduleNeeded module from PS App Gallery."
	$moduleTrack = Get-ModuleOrInstall -moduleName $moduleNeeded -requiredVersion "1.2.12"
	
	# If module was installed, import it
	if ($moduleTrack -eq "SUCCESS")
	{
		Write-Verbose -Message "Installation of $moduleNeeded was successful! Importing the module."
		
		$gsheetFinally += "Installation of $moduleNeeded was successful! Importing the module."
		Import-Module -Name $moduleNeeded
		
		try
		{
			## Stashing variables down here for testing...
			$scope = "https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file"
			$certPath = $null
			$saCertGCP = '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'
			$iss = 'intune-enrollment-sa@it-infrastructure-312317.iam.gserviceaccount.com'
			$certPswd = 'bm90YXNlY3JldA=='
			$accessToken = $null
			$SpreadsheetID = '1ZbOl2WShgsz_JloMXI-dNJwgniPWyr7s8EuWg1L3PUI'
			$sheetsArray = New-Object System.Collections.ArrayList($null)
			$sheetName = "Intune"
			$gapiCertificate = $null
			$gapiCertPath = "$scriptDirectory\it-infrastructure-312317-2e133a32e5bc.p12"
			
			$gapiCertificate = [System.Convert]::FromBase64String($saCertGCP)
			Set-Content -Path $gapiCertPath -Value $gapiCertificate -Encoding Byte -Verbose
			
			$tempCertPassword = [System.Text.Encoding]::UTF8.GetString($([System.Convert]::FromBase64String($certPswd)))
			
			# Set security protocol to TLS 1.2 to avoid TLS errors
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			
			<#
				For more information on the try, catch and finally keywords, see:
					Get-Help about_try_catch_finally
			#>
			
			# Try one or more commands
			try {
				# Google API Authorization
				$accessToken = Get-GOAuthTokenService -scope $scope -certPath $gapiCertPath -certPswd $tempCertPassword -iss $iss
				
				Write-Host "$accessToken" -ForegroundColor Magenta
			}
			# Catch all exceptions thrown by one of those commands
			catch
			{
				$err = $_.Exception
				$err | Select-Object -Property *
				"Response: "
				$err.Response
			}			
		}
		catch
		{
			Write-Error -Message "Failed to authenticate with Google API authentication services to pull down an access token. `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction Continue
		}
		
		## Send home logging information
		
		Write-Verbose -Message "Attempting to get contents of the transcript log file."
		Try
		{
			$transcriptLogContents = [IO.File]::ReadAllText("$logPath")
		}
		Catch
		{
			$transcriptLogContents = $_
		}
		
		Write-Verbose -Message "Get-ModuleOrInstall was executed with status [$moduleTrack]."
		
		# Upload CSV data to Google Sheets with Set-GSheetData
		$gsheetFinally += "Sending everything home!"
		
		$gsheetTranscriptLog = $transcriptLogContents
		
		$sheetsArray.Add(@($Env:Computername, $(Get-LogDate), $deployAppScriptVersion, $deployAppScriptDate, $scriptDirectory, $gsheetFunctionsLoaded, $gsheetRegistryBackupPath, $gsheetRegistryBackupResults, $gsheetCompanyInstall, $gsheetDsregDevice, $gsheetDsregSSOState, $gsheetDsregNgcPreq, $gsheetMDMEnrollment, $gsheetMDMAction, $gsheetMDMRegistryKeys, $gsheetMDMAgent, $gsheetGroupPolicy, $gsheetGpsvcLogAction, $gsheetEnrollmentCalled, $gsheetErrors, $gsheetFinally, $gsheetTranscriptLog)) | Out-Null
		
		<#
			For more information on the try, catch and finally keywords, see:
				Get-Help about_try_catch_finally
		#>
		
		# Try one or more commands
		try {
			Set-GSheetData -accessToken $accessToken -sheetName "Intune" -spreadSheetID $SpreadsheetID -values $sheetsArray -Append -Debug -Verbose
		}
		# Catch all other exceptions thrown by one of those commands
		catch
		{
			$err = $_.Exception
			$err | Select-Object -Property *
			"Response: "
			$err.Response
		}
		
		Start-Sleep -Seconds 5
		
		## Capture function's output
		$output = Remove-ModuleCleanup -moduleName $moduleNeeded
		
		# Write the function's output to the console
		Write-Verbose "$(Get-LogDate) Remove-ModuleCleanup was executed with status [$output]"
		
		Remove-Item $gapiCertPath
	}
	elseif (-Not ($moduleTrack -eq "SUCCESS")) {
		Write-Verbose -Message "Unfortunately the Google Sheets PowerShell module couldn't be installed. Skipping sending home data. :("
	}
	else
	{
		Write-Verbose -Message "Unable to determine if the Google Sheets PowerShell module could or could not be installed. Unable to send data home. :("
	}
	
	#endregion
	##*===============================================
	##* END SENDING TO GSHEETS
	##*===============================================
	
	# Stop logging
	Stop-Transcript
	
	Exit 0
}
# SIG # Begin signature block
# MIIiGwYJKoZIhvcNAQcCoIIiDDCCIggCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKFkuXs1/TBplW
# c/+KUiKRo7C4A3Tl7CP9yzVYT2/G9aCCHBIwggO+MIICpqADAgECAhB4nbqNO8Dt
# 5CR70kwbZeirMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMR0wGwYDVQQK
# ExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrU3ltYW50ZWMgTWFuYWdl
# ZCBQS0kgT25saW5lIFRlc3QgRHJpdmUgUm9vdDAeFw0xMTA4MTgwMDAwMDBaFw0y
# NjA4MTcyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBD
# b3Jwb3JhdGlvbjE0MDIGA1UEAxMrU3ltYW50ZWMgTWFuYWdlZCBQS0kgT25saW5l
# IFRlc3QgRHJpdmUgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AJxDl7mFTfIiKvkG4xk8Gl3cuCrgnZgbl4tJqQNaY1Xbos8Rxj4AgA2uFT1T9e+c
# Qs3PQIVw35cyenZ7EOMQMglSZzdB+zW7tzz90m1YW5OWOJtzFVe0Qe9x20Fhbib5
# Y3hF8W9w8r1wQ+5mE5E5qRek5FaivUHVmMj9meIyoVoUPsw4PnEdNxiIbmwwbbcV
# 1dBYPJ0FJWYx5jDSUImcFDcCa7qlqcFhEqWJaYAENDW1WlrFuDyNM0qwNrBqmaEp
# X/RoeiJl68mU0AhUlOiHkZKobNPjIVewnroAGZz/4RqqyPBbUkY6hhOqd+suoSJH
# QvfHWIHxJyi5NAl0i61naoMCAwEAAaNwMG4wEgYDVR0TAQH/BAgwBgEB/wIBADAO
# BgNVHQ8BAf8EBAMCAQYwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVZlcmlTaWdu
# TVBLSS0yLTkwMB0GA1UdDgQWBBSLePglpvOKySxIxopTC5bfhK+mbDANBgkqhkiG
# 9w0BAQsFAAOCAQEAlV38A3TS76d15azAUI5VUXjVIZp89I0PR1DLUyqs9nNxlD2S
# lf7YWAGV5+h4tHj6JGVjj7JXly8exst8puZuLQxIzOyETkbeEZCD6fwHgCsUS5eB
# +MkasrN25qxDoXDfOWBEyGQIJ2GBdaoaaZvSNRj3CgGbvTw43F7eN0I0+sSbWvOe
# yJVL9qrN/C0m+Ckl1WvuzAEI7sKyRoNKlVVNcfrfXX7Sjqg+2CoYatrGKnAE8Zlz
# 6O1PKlKjWRAQ6P7Ir9nZKh6fIHmQtXK60ySZiHsWIvNky3FMplb7Vuu3KHkBtvIG
# 1fb1rNtG8onrQDrNgidyix5cBPCsZdbnCNYb5jCCBYMwggNroAMCAQICDkXmuwOD
# M8OFZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowTDEgMB4GA1UE
# CxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24x
# EzARBgNVBAMTCkdsb2JhbFNpZ24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyug7hBkjMUpG9/6SrMxrCI
# a8W2idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDKRN5zlE7zp4l/T3hjCMgS
# UG1CZi9NuXkoTVIaihqAtxmBDn7EirxkTCEcQ2jXPTyKxbJm1ZCatzEGxb7ibTIG
# ph75ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yTu21T4kh8jBAHOP9msndh
# fuDqjDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvddOsqi250J3l1ELZDxgc1X
# kvp+vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwTV5O23rL44oW3c6K4NapF8uCdNqFv
# VIrxclZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxxN+Wm7CEIdfzmYRY/d9XZ
# kZeECmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4LsgizYWYJarEGOmWWWcDwNf3J
# 2iiNGhGHcIEKqJp1HZ46hgUAntuA1iX53AWeJ1lMdjlb6vmlodiDD9H/3zAR+YXP
# M0j1ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5bg6HGVxUsWW2v4yb3BPp
# DW+4LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRjPChMrwIDAQABo2MwYTAO
# BgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUrmwFo5MT
# 4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6Aw
# DQYJKoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCRaeZc0ITe3K2iT+hHeNZl
# mKlbqDyHfAKK0W63FnPmX8BUmNV0vsHN4hGRrSMYPd3hckSWtJVewHuOmXgWQxNW
# V7Oiszu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8QymZjjDTrCHg4x362Acz
# dlQAIiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABptArolXY2hMVHdVEYcTduZ
# lu8aHARcphXveOB5/l3bPqpMVf2aFalv4ab733Aw6cPuQkbtwpMFifp9Y3s/0HGB
# fADomK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2XH+CyB7+WBsoK6hsrV5t
# wAXSe7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTfbgZptt4KCUhZh+t7FGB6
# ZKppQ++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n7KQPTEX/07kwIwdMjxC/hpbZmVq0
# mVccpMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHioA7vugeXaX3yLSqGQdCWn
# sz5LyCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lfiy1DUutGDJTh9WZHeXfV
# VFsfrSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBluOYacW6gqPGC6EU+bNYC1wpngwVa
# yaQQMIIF/DCCBOSgAwIBAgIQL0mAxeZP31RinRvnUq3gYDANBgkqhkiG9w0BAQsF
# ADBiMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24x
# NDAyBgNVBAMTK1N5bWFudGVjIE1hbmFnZWQgUEtJIE9ubGluZSBUZXN0IERyaXZl
# IFJvb3QwHhcNMjIwNTEyMTc0NjM3WhcNMjIwNjEyMTc0NjM2WjBcMR0wGwYDVQQK
# DBRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECwwWRk9SIFRFU1QgUFVSUE9T
# RVMgT05MWTEaMBgGA1UEAwwRRW1tYW51ZWwuQ2FyZGVuYXMwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQC/GZ1/JhbKU0G9chJM64W2dU2aDWEFcHUfYkjG
# JaignJYfkrNweGVE1y7ThYAggFtOo4Tndy2pzqQJUd4o3xEdrMrqMTYhmVXAqQ3g
# New7cJmEF78c2ZLZD4w23fw6AGEVCFPwBH95dBtPEOiTJpO1K4A7rZ0H9rw/HKn1
# dWEaQKV/cxJwjmu/pHdGT6AVUl6uwpoUdrWGDS2RaXRGTtUpQMnaXVXAMyHwqla1
# tSW0s+SUh+VBTFUBYqAz8Fw9Bk0K8Q0x0OE5dGKZJlmbxAOZ3cXhV2LvYwhpSFyU
# JYDDT1OuBntsm8k2H9YMEgeT2KYNtlCjMm4XmWNRiyNvgdDNAgMBAAGjggKyMIIC
# rjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwID6DAiBgNVHSUBAf8EGDAWBggr
# BgEFBQcDAgYKKwYBBAGCNxQCAjAdBgNVHQ4EFgQUFX44R+d7lWvWM8K6vmQkMQK8
# M58wQAYDVR0RBDkwN6A1BgorBgEEAYI3FAIDoCcMJUVtbWFudWVsLkNhcmRlbmFz
# QHJlY3Vyc2lvbnBoYXJtYS5jb20wHwYDVR0jBBgwFoAUi3j4JabzisksSMaKUwuW
# 34SvpmwwNwYIKwYBBQUHAQEEKzApMCcGCCsGAQUFBzABhhtodHRwOi8vcGtpLW9j
# c3Auc3ltYXV0aC5jb20wXQYDVR0fBFYwVDBSoFCgToZMaHR0cDovL3BraS1jcmwu
# c3ltYXV0aC5jb20vY2FfY2VkN2Y4NjFmMTMwZWFhZGIzNWFkY2ZkNTUxZDc2MGIv
# TGF0ZXN0Q1JMLmNybDCB5AYDVR0gBIHcMIHZMIHWBgpghkgBhvhFAQcVMIHHMCYG
# CCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1dGguY29tL2NwczCBnAYIKwYBBQUH
# AgIwgY8MgYxUaGlzIHRlc3QgY2VydGlmaWNhdGUgaGFzIGJlZW4gaXNzdWVkIGZv
# ciB0aGUgc29sZSBwdXJwb3NlIG9mIGNvbmR1Y3RpbmcgcXVhbGl0eSBhc3N1cmFu
# Y2UgdGVzdGluZyBhbmQgc2hvdWxkIG5vdCBiZSB0cnVzdGVkIG9yIHJlbGllZCB1
# cG9uLjAuBgpghkgBhvhFARADBCAwHgYTYIZIAYb4RQEQAQQbAQSFrKGNLxYHMTQw
# MTgwNjA5BgpghkgBhvhFARAFBCswKQIBABYkYUhSMGNITTZMeTl3YTJrdGNtRXVj
# M2x0WVhWMGFDNWpiMjA9MA0GCSqGSIb3DQEBCwUAA4IBAQCSnGYT/o9F/ydvitzl
# 19e4rjAJ/sxubXlvLrixpzgd8OSEIX/OMm3F/v4LfElXAkgl167UM4ZycMfjrQWp
# W1jnKrCfi9Xc+0NQnrRgtrZp71FAEYYo9z86VGcPSV5IHkpOSAclquo0Hum+PpvS
# ek/RkzTgOosGfLkwLXnBfHYSoYE/Hn1Pb+61d8TJjnRDA/Cnd7XKtd+44YFVGUxl
# m6mGBgNZCzfFyGHi5rdI+MDAftOU0UqOgz9bsk3gkUBYTD1qmUoKRU6cFFlFrAM9
# lk4ZK9ffNL2bG8EnAavR8E9KFROMbaMqHwqv+mTW2hkVWWoEjYjKV+erMMdsolrR
# k6csMIIGWTCCBEGgAwIBAgINAewckkDe/S5AXXxHdDANBgkqhkiG9w0BAQwFADBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODA2MjAwMDAwMDBaFw0z
# NDEyMTAwMDAwMDBaMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNI
# QTM4NCAtIEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8ALiMCP6
# 4BvhmnSzr3WDX6lHUsdhOmN8OSN5bXT8MeR0EhmW+s4nYluuB4on7lejxDXtszTH
# rMMM64BmbdEoSsEsu7lw8nKujPeZWl12rr9EqHxBJI6PusVP/zZBq6ct/XhOQ4j+
# kxkX2e4xz7yKO25qxIjw7pf23PMYoEuZHA6HpybhiMmg5ZninvScTD9dW+y279Jl
# z0ULVD2xVFMHi5luuFSZiqgxkjvyen38DljfgWrhsGweZYIq1CHHlP5CljvxC7F/
# f0aYDoc9emXr0VapLr37WD21hfpTmU1bdO1yS6INgjcZDNCr6lrB7w/Vmbk/9E81
# 8ZwP0zcTUtklNO2W7/hn6gi+j0l6/5Cx1PcpFdf5DV3Wh0MedMRwKLSAe70qm7uE
# 4Q6sbw25tfZtVv6KHQk+JA5nJsf8sg2glLCylMx75mf+pliy1NhBEsFV/W6Rxbux
# TAhLntRCBm8bGNU26mSuzv31BebiZtAOBSGssREGIxnk+wU0ROoIrp1JZxGLguWt
# WoanZv0zAwHemSX5cW7pnF0CTGA8zwKPAf1y7pLxpxLeQhJN7Kkm5XcCrA5XDAnR
# YZ4miPzIsk3bZPBFn7rBP1Sj2HYClWxqjcoiXPYMBOMp+kuwHNM3dITZHWarNHOP
# Hn18XpbWPRmwl+qMUJFtr1eGfhA3HWsaFN8CAwEAAaOCASkwggElMA4GA1UdDwEB
# /wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTqFsZp5+PLV0U5
# M6TwQL7Qw71lljAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDA+Bggr
# BgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWdu
# LmNvbS9yb290cjYwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXI2LmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggIBAH/iiNlXZytCX4GnCQu6xLsoGFbWTL/bGwdwxvsLCa0A
# OmAzHznGFmsZQEklCB7km/fWpA2PHpbyhqIX3kG/T+G8q83uwCOMxoX+SxUk+RhE
# 7B/CpKzQss/swlZlHb1/9t6CyLefYdO1RkiYlwJnehaVSttixtCzAsw0SEVV3ezp
# Sp9eFO1yEHF2cNIPlvPqN1eUkRiv3I2ZOBlYwqmhfqJuFSbqtPl/KufnSGRpL9Ka
# oXL29yRLdFp9coY1swJXH4uc/LusTN763lNMg/0SsbZJVU91naxvSsguarnKiMMS
# ME6yCHOfXqHWmc7pfUuWLMwWaxjN5Fk3hgks4kXWss1ugnWl2o0et1sviC49ffHy
# kTAFnM57fKDFrK9RBvARxx0wxVFWYOh8lT0i49UKJFMnl4D6SIknLHniPOWbHuOq
# hIKJPsBK9SH+YhDtHTD89szqSCd8i3VCf2vL86VrlR8EWDQKie2CUOTRe6jJ5r5I
# qitV2Y23JSAOG1Gg1GOqg+pscmFKyfpDxMZXxZ22PLCLsLkcMe+97xTYFEBsIB3C
# LegLxo1tjLZx7VIh/j72n585Gq6s0i96ILH0rKod4i0UnfqWah3GPMrz2Ry/U02k
# R1l8lcRDQfkl4iwQfoH5DZSnffK1CfXYYHJAUJUg1ENEvvqglecgWbZ4xqRqqiKb
# MIIGaDCCBFCgAwIBAgIQAUiQPcKKvKehGU0MHFe4KTANBgkqhkiG9w0BAQsFADBb
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UE
# AxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDAeFw0y
# MjA0MDYwNzQxNThaFw0zMzA1MDgwNzQxNThaMGMxCzAJBgNVBAYTAkJFMRkwFwYD
# VQQKDBBHbG9iYWxTaWduIG52LXNhMTkwNwYDVQQDDDBHbG9iYWxzaWduIFRTQSBm
# b3IgTVMgQXV0aGVudGljb2RlIEFkdmFuY2VkIC0gRzQwggGiMA0GCSqGSIb3DQEB
# AQUAA4IBjwAwggGKAoIBgQDCydwDthtQ+ioN6JykIdsopx31gLUSdCP+Xi/DGl2W
# siAZGVBfdiMmNcYh7JTvtaI6xZCBmyHvCyek4xdkO9qT1FYvPNdY+W2swC+QeCNJ
# wPjBj3AT1GvfJohadntI9+Gkpu8LGvMlVA+AniMSEhPRsPcC4ysN/0A+AEJD3hrv
# TPSHqfKePNAG5+Jj0utMW91dWJTT5aU5KKoHXnYjMPz8f5gNxWVtG9V0RTpGsKIW
# dd6iwipwfLZ2vNkbrrpdnPaHlc6qqOK1o7GTbkClmxCIdhZONKH8nvHhGlTRyCRX
# lHatwsfso6OWdeLGKGsCBehLubXgUit4AYwqMSxM6AXlb58PhCYuaGz6y00ZfBjB
# /2oaqcu+o3X46cgYsszdL0FAIBzPiAsXybCKQ8via5NR8RG+Qrz4UfLaAAK+CBgo
# BSfE3DtddykeGdRBKmZ9tFJzXEKlkNONxaOqN85zAZQkGUJD0ZSPS37dy228G057
# +aoLIktJgElwGy1P3jRgPr0CAwEAAaOCAZ4wggGaMA4GA1UdDwEB/wQEAwIHgDAW
# BgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUW2t79HB0CMENKsjv8cS5
# QNJKxv0wTAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0
# cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDAYDVR0TAQH/BAIw
# ADCBkAYIKwYBBQUHAQEEgYMwgYAwOQYIKwYBBQUHMAGGLWh0dHA6Ly9vY3NwLmds
# b2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEzODRnNDBDBggrBgEFBQcwAoY3aHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3N0c2FjYXNoYTM4NGc0
# LmNydDAfBgNVHSMEGDAWgBTqFsZp5+PLV0U5M6TwQL7Qw71lljBBBgNVHR8EOjA4
# MDagNKAyhjBodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEz
# ODRnNC5jcmwwDQYJKoZIhvcNAQELBQADggIBAC5rPo9/sLBg2fGdhNyVtt9fDb8k
# UeMaBqpVBMthwe9lca4L/ZQkVwDH5PYMvBiVfS8ZamAzpr7QCFVWBLbj/h675RB2
# VDurXCFeKjVNRsumTLoEQGBgLNvT9p3eyjIQDHiwu1bFB0twvKcPq3K8jcvr7sFM
# a9n6mKF0PumoyHl8dndI/c/j8A3B6cOS4AcMEy8/a3812dW37m98WMDxPwwZsgKj
# SUycBMPwtJen4E1qJbo0FmJmyHi8aXOqX3KiNVgeJuu/MhSqEnrr9JZrf3Ks6qc5
# CDMBNj5hJH4RnREediJU40C7LoYMdp5p0sQcPaILjIgEA1Te6RsX/iwrntnWWyI4
# /GRAhs0Xf+Gpn7m/kkGobyZq9A8osECRkC9OtnZQvE0j2X9Pa5Mpp2zn0DA+qZMf
# wlArOcWy+E0nJNH9dti++ZP0qVQK1XZY0Tye6hroJMT7NvEvWdOSw+zLYFIeHEYl
# CP9+2ZOuFJWohooHLlSLc0w3FThQVofxT64cj8mhbC8L/Lscby29qrbraCPw7ZQn
# FGPLrPRniiyB0xQSGAE/hHqu7EdgP2hYmclKwqGZFQXCrd6i79enVXy8hBtNlLuO
# SoVE2YE9qqMlVV+ka802bAD5/3LeWuz/yaBBlhpAaoWRHK91Y6jLWjO1lDN+so0P
# c76H/K86cx97INtyMYIFXzCCBVsCAQEwdjBiMQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xNDAyBgNVBAMTK1N5bWFudGVjIE1hbmFn
# ZWQgUEtJIE9ubGluZSBUZXN0IERyaXZlIFJvb3QCEC9JgMXmT99UYp0b51Kt4GAw
# DQYJYIZIAWUDBAIBBQCgTDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkq
# hkiG9w0BCQQxIgQgXAAPsy6xB0Fmqi9qdEmnkNa4VtSNEWQvkd6qpEr5hmYwDQYJ
# KoZIhvcNAQEBBQAEggEAGlF6geRlMEGLFylYI8lOZgduiR/AHGn1NPP6lUf/jmh+
# JG8W9TWaHryQyFk6m8IJbvkwcQwS3E+B6g/MUlVXdIse7rpA8gryyxL3waebDDVF
# wzBmMf8CtXp1nKh5JgudzdjZ3I4ivbkGebsUyh2WBDIBRU4C1EZ2Z/pSqD0G65QU
# 00SdqJwxyO1kyRYB+d1Q1a3JXpnXXmGd6R1l42+Zz83bJorc2SVga/XPhu9xz8HM
# 4un74L/1gzeDtxt0kkVIEEYzAlaScD0T8+ZX5vdM5+8m/E2PG4X24oWkf8ZTkv+y
# pGpmVoLF465GGFFWFCwmQ1Rd2CwPnytviQNenn9CV6GCA2wwggNoBgkqhkiG9w0B
# CQYxggNZMIIDVQIBATBvMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxT
# aWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAt
# IFNIQTM4NCAtIEc0AhABSJA9woq8p6EZTQwcV7gpMAsGCWCGSAFlAwQCAaCCAT0w
# GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNjAy
# MTkzNTE5WjArBgkqhkiG9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaENBgkqhkiG9w0B
# AQsFADAvBgkqhkiG9w0BCQQxIgQgdXYYHpfqk82IoiaSAUKNxZA4kLRY8UdGVe+e
# aErPbu0wgaQGCyqGSIb3DQEJEAIMMYGUMIGRMIGOMIGLBBQxAw4XaqRZLqssi63o
# Mpn8tVhdzzBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQAUiQPcKKvKehGU0MHFe4KTANBgkqhkiG9w0BAQsFAASCAYC2
# CTVg26rpqMaHlwvMJynrRV0XpPxEMS0129ueRPoL0oew1tX3ldLq9igIQEL4M7J8
# Psi+DZ6oobKgbOENaRSDu786452DjOxGVpa0YRiC8CNWViaPSDHMZ9VKitKegflW
# c8DML3Z1YCj/H2do5XMzQTqBC/EbNmMVNapPXlkZ1qBtcXj8Asl0uak5C86EyVs1
# rvAA37Rt0v8iho4wNb6HIp8mhX73oe5Yg4jkchkZFczb0I2rc6x64h/m1qLRnpF3
# 4WBElmcmt/7PyIjVj/+7mVszsoQ+zC84ut6ZHPAgqjKcJi4ylwF2lFf6XViHijIX
# rrNnvXch6TJzcCM9C6D8RaeBtChRv8H+We6gljrA3jOVEKZlwKY3SYH1Wt68ZEYk
# M05Z5nfUDwx7KYiWt1bLM4LKZOYf5vPgxd6D66d7YVEXtIWIRzHov6sHrERzKtP7
# stIWpt38sWPFoTyXCAjy5bztjziDmbZ8KBbAqwZCyqKivgYDQTZwoaK+p+/9PDg=
# SIG # End signature block
