$AddACL = New-Object System.Security.AccessControl.RegistryAccessRule ("Everyone","FullControl","ObjectInherit,ContainerInherit","None","Allow")
$owner = [System.Security.Principal.NTAccount]"Administrators"
$keyCR = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("CLSID\{76A64158-CB41-11D1-8B02-00600806D9B6}",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
# Get a blank ACL since you don't have access and need ownership
$aclCR = $keyCR.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
$aclCR.SetOwner($owner)
$keyCR.SetAccessControl($aclCR)
# Get the acl and modify it
$aclCR = $keyCR.GetAccessControl()
$aclCR.SetAccessRule($AddACL)
$keyCR.SetAccessControl($aclCR)
$keyCR.Close()
Set-ItemProperty -Path "HKEY:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value "4" -Force
