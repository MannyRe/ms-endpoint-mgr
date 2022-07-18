# Intune Enrollment

A custom PowerShell script created by Manny to enroll devices into Intune and remove Meraki.

## Requirements and Dependencies

This uses the Microsoft Win32 Content Prep Tool (a.k.a. IntuneWinAppUtil.exe, available from https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool) to package the PowerShell script and related files into a .intunewin file that can be uploaded to Intune as a Win32 app. 

List any additional Requirements and Dependencies

## Building

Run the makeapp.cmd file from a command prompt.  (It will not work if you using Terminal.)

## Using

Add the resulting Win32 app (.intunewin) to Intune.  The installation command line should be:

Deploy-Application.exe -DeploymentType Install -DeployMode Silent -AllowRebootPassThru

The uninstall command line should be:

Deploy-Application.exe -DeploymentType Uninstall -DeployMode Silent -AllowRebootPassThru

Detection:
<Detection type/rule goes here>

## Notes

Any extra information goes here.
