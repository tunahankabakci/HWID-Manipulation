using System;
using System.IO;
using System.Reflection;
using System.Runtime.Remoting;
using EasyHook;
using hwid_bypass;

namespace easyhook
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            // Will contain the name of the IPC server channel
            string channelName = null;

            // Process command line arguments or print instructions and retrieve argument value
            ProcessArgs(out var targetPid);

            // Create the IPC server using the FileMonitorIPC.ServiceInterface class as a singleton
            RemoteHooking.IpcCreateServer<ServerInterface>
                (ref channelName, WellKnownObjectMode.Singleton);

            // Get the full path to the assembly we want to inject into the target process
            var injectionLibrary =
                Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty,
                    "HWID-Bypass.dll");

            try
            {
                // Injecting into existing process by Id
                if (targetPid > 0)
                {
                    Console.WriteLine("Attempting to inject into process {0}", targetPid);

                    // inject into existing process
                    RemoteHooking.Inject(
                        targetPid, // ID of process to inject into
                        injectionLibrary, // 32-bit library to inject (if target is 32-bit)
                        injectionLibrary, // 64-bit library to inject (if target is 64-bit)
                        channelName // the parameters to pass into injected library
                        // ...
                    );
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("There was an error while injecting into target:");
                Console.ResetColor();
                Console.WriteLine(e.ToString());
            }

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("<Press any key to exit>");
            Console.ResetColor();
            Console.ReadKey();
        }

        private static void ProcessArgs(out int targetPid)
        {
            Console.WriteLine("Enter a process Id");
            targetPid = int.Parse(Console.ReadLine() ?? string.Empty);
        }
    }
}