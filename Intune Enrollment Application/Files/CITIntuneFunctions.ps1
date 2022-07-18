<#
.SYNOPSIS
	This file is dot sourced file with functions that are to be imported into another project.
.DESCRIPTION
    The functions included in this file are mainly for the CITIntuneDeploymentInfo.ps1 script.

.EXAMPLE
    . .\CITIntuneFunctions.ps1
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
.LINK
	Conact Manny for more information: manny@recursion.com
#>

# Functions ( •_•)>⌐■-■    (⌐■_■)

<#
    Function Name: Get-MSIGUID
    Description: Finds the passed program's GUID
    Return: $o for GUID
#>
Function Get-MSIGUID {
    [cmdletbinding()]
    Param (
        [string]$msiName
    )
    # End of Parameters
    Process {
        # Initalizing variables
        $o = $null
        $check = $null
        $functionName = "[FUNCTION: {0}]" -f $MyInvocation.MyCommand

        # Write to console the function was called
        Write-Verbose -Message "$(Get-LogDate) $functionName was called and is executing"

        # Find passed name of package's GUID in registry.
        $o = get-wmiobject Win32_Product | Sort-Object -Property Name | Where-Object Name -EQ $msiName | Select-Object IdentifyingNumber | ForEach-Object { $_.IdentifyingNumber }

        # Checks if the output is null or empty.
        $check = [string]::IsNullOrWhiteSpace($o)

        # Determine if the output is null or empty. Either error out or pass found GUID.
        if ($check) {
            # Send error message to host
            Write-Error -Message "$(Get-LogDate) $functionName Failed to find the specified win32 package's ($msiName)" -ErrorAction 'Continue'
            
            # True tells the next function this function failed.
            $o = $true
            return $o
        }
        elseif (-NOT ($check)) {
            # Send sucess message to host
            Write-Verbose -Message "$(Get-LogDate) $functionName Found the passed win32 package's ($msiName) GUID ($o)"
            return $o
        }
        else {
            # If the function somehow ends up here, return TRUE.
            Write-Error -Message "$(Get-LogDate) $functionName Invalid function path. An error may have occured with the fuction." -ErrorAction 'Continue'

            # True tells the next function this function failed.
            $o = $true
            return $o
        }
    } # End of Process
}

<#
    Function Name: Get-GUIDName
    Description: Finds the passed GUID package name
    Return: $o for package name
#>
Function Get-GUIDName {
    [cmdletbinding()]
    Param (
        [string]$identNumber
    )
    # End of Parameters
    Process {
        # Initalizing variables
        $o = $null
        $functionName = "[FUNCTION: {0}]" -f $MyInvocation.MyCommand

        # Write to console the function was called
        Write-Host "$(Get-LogDate) $functionName was called and is executing" -BackgroundColor Black -ForegroundColor Yellow

        # Write to console function is executing
        Write-Host "$(Get-LogDate) $functionName Attempting to grab GUID's ($identNumber) package name"  -BackgroundColor Black -ForegroundColor Yellow

        # Check if passed value is not equal to true
        if (-NOT ($identNumber -eq $true)) {
            # Find passed name of package's GUID in registry.
            $o = get-wmiobject Win32_Product | Sort-Object -Property IdentifyingNumber | Where-Object IdentifyingNumber -EQ $identNumber | Select-Object Name | ForEach-Object { $_.Name }

            # Write to console the GUID's package name
            Write-Host "$(Get-LogDate) $functionName Found the GUID's ($identNumber) package name ($o)"  -BackgroundColor Black -ForegroundColor Green
            
            # Return the package name
            return $o
        }
        else {
            # Write to console failure to find GUID's package name
            Write-Host "$(Get-LogDate) $functionName An error occured while looking up GUID's ($identNumber) package name"  -BackgroundColor Black -ForegroundColor Red

            # Set output to FAILED and return
            $o = "FAILED"
            return $o
        }        
    } # End of Process
}

<#
    Function Name: Start-ProcessWithLog
    Description: Executes Start-Process cmdlet with logging
    Return: $processObject contains a custom psobject with:
            execution exit code, passed execution filename, and passed arguments.
#>
Function Start-ProcessWithLog {
    [cmdletbinding()]
    Param (
        [string]$fileName, [array]$arguments
    )
    # End of Parameters
    Process {
        # Initalizing variables
        $functionName = "[FUNCTION: {0}]" -f $MyInvocation.MyCommand
        $psi = $null
        $process = $null
        $exitCode = $null

        # Write to console the function was called
        Write-Host "$(Get-LogDate) $functionName was called and is executing" -BackgroundColor Black -ForegroundColor Yellow

        # Grab underlying diagnostic process of Start-Process
        $psi = New-object System.Diagnostics.ProcessStartInfo 
        $psi.CreateNoWindow = $true 
        $psi.UseShellExecute = $false 
        $psi.RedirectStandardOutput = $true 
        $psi.RedirectStandardError = $true 
        $psi.FileName = "$fileName"
        $psi.Arguments = $arguments
        $process = New-Object System.Diagnostics.Process 
        $process.StartInfo = $psi
        [void]$process.Start()
        $process.WaitForExit()
        $exitCode = $process.ExitCode

        # Hashtable to add properties to custom psobject
        [hashtable]$processProperty = @{}

        # Add values to hashtable.
        $processProperty.Add('ExitCode', $exitCode)
        $processProperty.Add('FileName', $fileName)
        $processProperty.Add('Arguments', $arguments)
        # Create psobject and add hashtable properties
        $processObject = New-Object -TypeName psobject -Property $processProperty

        # Write to console the exit code
        Write-Host "$(Get-LogDate) $functionName Exit Code: $($processObject.ExitCode)" -BackgroundColor Black -ForegroundColor Yellow

        # Write to console the process name and arguments that were passed
        Write-Host "$(Get-LogDate) $functionName Completed Start-Process with the following arugments: $($processObject.FileName) | $($processObject.Arguments)" -BackgroundColor Black -ForegroundColor Green
        
        # Return the custom psobject
        return $processObject
        
    } # End of Process
}

<#
    Function Name: Remove-MSIPackage
    Description: Removes the specified GUID package
    Return: $o for feedback
#>
Function Remove-MSIPackage {
    [cmdletbinding()]
    Param (
        [string]$guid
    )
    # End of Parameters
    Process {
        # Initalizing variables
        $o = $null
        $process = $null
        $functionName = "[FUNCTION: {0}]" -f $MyInvocation.MyCommand
        $packageName = $(Get-GUIDName -identNumber $guid)
        $successCodes = @(
            '0'
            '1641'
        ) # msiexec success codes
        $MSIArguments = @(
            "/x"
            "$guid"
            "/quiet"
            "/norestart"
        ) # Create an array with msi arguments

        # Write to console the function was called
        Write-Host "$(Get-LogDate) $functionName was called and is executing" -BackgroundColor Black -ForegroundColor Yellow
        
        if (-NOT ($guid -eq $true)) {
            # Send sucess message to host
            Write-Host "$(Get-LogDate) $functionName Removing MSI package $packageName GUID ($guid) with the following arguments $MSIArguments" -BackgroundColor Black -ForegroundColor Yellow

            # Capture output of function and execute function
            $process = Start-ProcessWithLog -fileName "msiexec.exe" -arguments $MSIArguments

            # check with regular expression if the exitcode matches the success codes. return true or false
            if ($null -ne ($process.ExitCode | Where-Object { $successCodes -match $_ })) {
                #IF STATEMENT: If TRUE then success

                # Write to console the process compleeted successfully
                Write-Host "$(Get-LogDate) $functionName $($process.FileName) was executed successfully with arguments ($($process.Arguments)) and exit code ($($process.ExitCode))"  -BackgroundColor Black -ForegroundColor Green

                # Write to console the computer does not require a restart
                Write-Host "$(Get-LogDate) $functionName A reboot of the system $($env:COMPUTERNAME) is NOT required to completely remove $packageName." -BackgroundColor Black -ForegroundColor Magenta

                # Set output to SUECESS and return
                $o = "SUCCESS"
                return $o
            }
            elseif ($process.ExitCode -eq 3010) {
                # ELSEIF STATEMENT: 3010 is a success exit code but requires a restart

                # Write to console the process compleeted successfully
                Write-Host "$(Get-LogDate) $functionName $($process.FileName) was executed successfully with arguments ($($process.Arguments)) and exit code ($($process.ExitCode))"  -BackgroundColor Black -ForegroundColor Green

                # Write to console the computer requires a restart
                Write-Host "$(Get-LogDate) $functionName A reboot of the system $($env:COMPUTERNAME) IS required to completely remove $packageName." -BackgroundColor Black -ForegroundColor Magenta

                # Set output to SUECESS and return
                $o = "SUCCESS"
                return $o
            }
            else {
                # ELSE STATEMENT: Catch all based on exit codes, this route will capture all failure exit codes

                # Write to console the executed process failed to execute with the passed arguments and exit code
                Write-Host "$(Get-LogDate) $functionName $($process.FileName) failed to execute with arguments ($($process.Arguments)) and exit code ($($process.ExitCode))"  -BackgroundColor Black -ForegroundColor Red
                
                # Set output to FAILED status and return
                $o = "FAILED"
                return $o
            }
        }
        else {
            # ELSE STATEMENT: Catch all unexpected conditions

            # Write to console the passed GUID is invalid
            Write-Host "$(Get-LogDate) $functionName Invalid GUID was passed ($guid). This package either doesn't exist or a lookup error occured." -BackgroundColor Black -ForegroundColor Red
            
            # Set output to FAILED status and return
            $o = "FAILED"
            return $o
        }
    } # End of Process
}

<#
    Function Name: Get-ModuleOrInstall
    Description: Determines if a specified module is install. If not, it installs
    Return: $o for output information
#>
Function Get-ModuleOrInstall {
    [cmdletbinding()]
    Param (
        [string]$moduleName, [string]$requiredVersion
    )
    # End of Parameters
    Process {
        # Initalizing variables
        $o = $null
        $functionName = "[FUNCTION: {0}]" -f $MyInvocation.MyCommand
        $moduleCheck = $(Get-Module -ListAvailable -Name $moduleName -Refresh | ForEach-Object { $_.Name })
        $details = $null
        $moduleInfo = $null

        # Write to console the function was called
        Write-Host "$(Get-LogDate) $functionName was called and is executing" -BackgroundColor Black -ForegroundColor Yellow

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $null = Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201 -Force

        # check with regular expression if the exitcode matches the success codes. return true or false
        if ($null -ne ($moduleCheck | Where-Object { $moduleName -match $_ })) {
            #IF STATEMENT: If TRUE then success

            $details = Get-Module -ListAvailable -Name $moduleCheck -Refresh
        
            # Write to console the module was found, no install needed
            Write-Host "$(Get-LogDate) $functionName $moduleName is installed, here's the details:" -BackgroundColor Black -ForegroundColor Green
            Write-Host "Name: $($details.Name)`nVersion: $($details.Version)`nPath: $($details.Path)" -BackgroundColor Black -ForegroundColor Magenta

            # Set output to TRUE and return
            $o = "SUCCESS"
            return $o
        }
        else {
            # ELSE STATEMENT: Catch all based on exit codes, this route will capture all failure exit codes
        
            # Write to console the module was not found, an install of the module is needed
            Write-Host "$(Get-LogDate) $functionName $moduleName is not installed, an installation is needed" -BackgroundColor Black -ForegroundColor Cyan

            Install-Module -Name PowerShellGet -Force -AllowClobber
            Update-Module -Name PowerShellGet -Force

            Try {
                Install-Module -Name $moduleName -RequiredVersion $requiredVersion -ErrorAction:Stop -OutVariable moduleInfo -Force
                Write-Host "$(Get-LogDate) $functionName Results of attempting to install $moduleName is:" -BackgroundColor Black -ForegroundColor Cyan

                Write-Host "$(Get-LogDate) $functionName Successfully installed PowerShell module: $moduleName" -BackgroundColor Black -ForegroundColor Green
                # Set output to SUCCESS status and return
                $o = "SUCCESS"
                return $o
            }
            Catch {                
                Write-Host $_ -BackgroundColor Black -ForegroundColor Red

                Write-Host "$(Get-LogDate) $functionName Failed to install PowerShell module: $moduleName" -BackgroundColor Black -ForegroundColor Red
                # Set output to FAILED status and return
                $o = "FAILED"
                return $o
            }
    
            Write-Host $moduleInfo

            Write-Host "$(Get-LogDate) $functionName Failed to install PowerShell module: $moduleName" -BackgroundColor Black -ForegroundColor Red
            # Set output to FAILED status and return
            $o = "FAILED"
            return $o
        }
    } # End of Process
}

<#
    Function Name: Remove-ModuleCleanup
    Description: Meant for cleanup to remove the installed module
    Return: $o for output information
#>
Function Remove-ModuleCleanup {
    [cmdletbinding()]
    Param (
        [string]$moduleName
    )
    # End of Parameters
    Process {
        # Initalizing variables
        $o = $null
        $functionName = "[FUNCTION: {0}]" -f $MyInvocation.MyCommand

        # Write to console the function was called
        Write-Host "$(Get-LogDate) $functionName was called and is executing" -BackgroundColor Black -ForegroundColor Yellow
        
        # Write to console the module was not found, an install of the module is needed
        Write-Host "$(Get-LogDate) $functionName Uninstalling $moduleName PowerShell Module" -BackgroundColor Black -ForegroundColor Cyan

        Try {
            Uninstall-Module -Name $moduleName -ErrorAction Stop -OutVariable moduleInfo -Force
            Write-Host "$(Get-LogDate) $functionName Results of attempting to uninstall $moduleName is:" -BackgroundColor Black -ForegroundColor Cyan

            Write-Host "$(Get-LogDate) $functionName Successfully uninstalled PowerShell module: $moduleName" -BackgroundColor Black -ForegroundColor Green
            # Set output to FAILED status and return
            $o = "SUCCESS"
            return $o
        }
        Catch {                
            Write-Host $_ -BackgroundColor Black -ForegroundColor Red

            Write-Host "$(Get-LogDate) $functionName Failed to unininstall PowerShell module: $moduleName" -BackgroundColor Black -ForegroundColor Red
            # Set output to FAILED status and return
            $o = "FAILED"
            return $o
        }

        Write-Host $moduleInfo

        Write-Host "$(Get-LogDate) $functionName Failed to unininstall PowerShell module: $moduleName" -BackgroundColor Black -ForegroundColor Red
        # Set output to FAILED status and return
        $o = "FAILED"
        return $o
    } # End of Process
}

<#
    Function Name: Get-LogDate
    Description: Gets strict ISO 8601 format
    Return: $o for date
#>
Function Get-LogDate {
    Process {
        # Initialize variables
        $o = $null

        # Get ISO 8601 date with brackets
        $o = "[{0}]" -f $(Get-Date -format s)

        return $o
    } # End of Process
}

function Invoke-TranslateMDMEnrollmentType {
    <#
    .SYNOPSIS
         This function translates the MDM Enrollment Type in a readable string.
    .DESCRIPTION
         This function translates the MDM Enrollment Type in a readable string.
 
    .EXAMPLE
         Invoke-TranslateMDMEnrollmentType
    .NOTES
        Credit: https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.14/Content/Internal%5CInvoke-TranslateMDMEnrollmentType.ps1
    #>
    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Int]$Id
    )
    switch ($Id) {
        0 { "Not enrolled" }
        6 { "MDM enrolled" }
        13 { "Azure AD joined" }
    }
}

function Get-MDMEnrollmentStatus {
    <#
    .Synopsis
    Get Windows 10 MDM Enrollment Status.
 
    .Description
    Get Windows 10 MDM Enrollment Status with Translated Error Codes.
 
    Returns $null if Device is not enrolled to an MDM.
 
    .Example
    # Get Windows 10 MDM Enrollment status
    Get-MDMEnrollmentStatus
    
    .NOTES
    Credit: https://www.powershellgallery.com/packages/ModernWorkplaceClientCenter/0.1.11/Content/Functions%5CGet-MDMEnrollmentStatus.ps1
    #>
    Process {
        #Locate correct Enrollment Key
        $EnrollmentKey = Get-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* | Get-ItemProperty | Where-Object -FilterScript { $null -ne $_.UPN }
        if ($EnrollmentKey) {
            Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value (Invoke-TranslateMDMEnrollmentType -Id ($EnrollmentKey.EnrollmentType))
        }
        else {
            Write-Error "Device is not enrolled to MDM."
        }
        return $EnrollmentKey
    } # End of Process
}

function Test-RegistryValue {
    <#
    .Synopsis
    Determine if registry key and value exists.
 
    .Description
    The function uses Get-ItemProperty to determine if the key value passed in exists.
 
    .Example
    # Test registry path
    Test-RegistryValue -Path 'HKLM:\SOFTWARE\TestSoftware' -Value 'Banana'
    
    .NOTES
    Credit: https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
    #>
    param (
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value
    )
    Process {
        try {
            $gpoLogicFailPass = Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Continue

            if (-Not ($null -eq$gpoLogicFailPass)) {
                return $true
            }
            return $false
        }
    
        catch {
    
            return $false
    
        }

    }
	
}

<#
    Function Name: New-DiagBox
    Description: Creates a dialog box to display a message
    Return: $o for selection choice
#>
Function New-DiagBox
{
	[cmdletbinding()]
	Param (
		[string]$msgTitle,
		[string]$msgButton,
		[string]$msgIcon,
		[string]$msgBody
	)
	# End of Parameters
	Process
	{
		# Message variables for Yes/No prompt
		$o = $null
		$outTitle = $msgTitle
		$outButton = [System.Windows.MessageBoxButton]::$msgButton
		$outIcon = [System.Windows.MessageBoxImage]::$msgIcon
		$outBody = $msgBody
		
		## Use the following each time your want to prompt the use
		$o = [System.Windows.MessageBox]::Show($outbody, $outTitle, $outButton, $outIcon)
		
		return $o
	} # End of Process
}


## End of Functions
