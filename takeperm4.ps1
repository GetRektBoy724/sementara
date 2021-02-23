$regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
 
Try  {
        Get-ItemProperty $regPath -ErrorAction Stop        
        $regACL = Get-ACL $regPath
        $regRule= New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","FullControl","Allow")
        $regACL.SetAccessRule($regRule)
        Set-Acl $regPath $regACL
        Write-Host "Success!"
      }
 
Catch {
             
         Write-Host "Failed!"
      }
