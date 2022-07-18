# Intune Enrollment

A custom PowerShell script created by Manny to enroll devices into Intune and remove Meraki.

## Requirements and Dependencies

This uses the [PSAppDeployToolkit](https://psappdeploytoolkit.com/) to package the PowerShell script and related files into a .msi file that can be used to cache the necessary script files and run. 

## Using
You can use the provided pre-built MSI file (built with [PowerShell Studio 2022](https://www.sapien.com/store/powershell-studio)) or run the [CITIntuneDeploymentInfo.ps1](Files/CITIntuneDeploymentInfo.ps1) PowerShell script directly.

### MSI Install
Run the SilentIntuneDeployment.msi Microsoft Installer package.

### PowerShell script
Run the [CITIntuneDeploymentInfo.ps1](Files/CITIntuneDeploymentInfo.ps1) PowerShell script in an elevated PowerShell window.


## Notes

* The MSI package is silent and will not display an installer workflow process. You will still see necessary Windows pop-up.
