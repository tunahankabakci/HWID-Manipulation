using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;
using Microsoft.Win32;

namespace hwid_bypass;

#region init

public class InjectionEntryPoint : IEntryPoint
{
    private readonly ServerInterface _server;
    private readonly Queue<string> _messageQueue = new();

    public InjectionEntryPoint(
        RemoteHooking.IContext context,
        string channelName)
    {
        // Connect to server object using provided channel name
        _server = RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

        // If Ping fails then the Run method will be not be called
        _server.Ping();
    }

    public void Run(
        RemoteHooking.IContext context,
        string channelName)
    {
        // Injection is now complete and the server interface is connected
        _server.IsInstalled(RemoteHooking.GetCurrentProcessId());

        #endregion

        // Install hooks

        var getVolumeInformationHookW = LocalHook.Create(
            LocalHook.GetProcAddress("kernel32.dll", "GetVolumeInformationW"),
            new GetVolumeInformationDelegate(GetVolumeInformation_Hook),
            this);

        var getAdaptersInfoHook = LocalHook.Create(
            LocalHook.GetProcAddress("iphlpapi.dll", "GetAdaptersInfo"),
            new GetAdaptersInfoDelegate(GetAdaptersInfo_Hook),
            this);

        var regGetValueHookW = LocalHook.Create(
            LocalHook.GetProcAddress("advapi32.dll", "RegGetValueW"),
            new RegGetValueDelegate(RegGetValue_Hook),
            this);

        var getVolumeInformationHookA = LocalHook.Create(
            LocalHook.GetProcAddress("kernel32.dll", "GetVolumeInformationA"),
            new GetVolumeInformationDelegate(GetVolumeInformation_Hook),
            this);

        var getCurrentHwProfileHookA = LocalHook.Create(
            LocalHook.GetProcAddress("advapi32.dll", "GetCurrentHwProfileA"),
            new GetCurrentHwProfileDelegate(GetCurrentHwProfile_Hook),
            this);

        var getCurrentHwProfileHookW = LocalHook.Create(
            LocalHook.GetProcAddress("advapi32.dll", "GetCurrentHwProfileW"),
            new GetCurrentHwProfileDelegate(GetCurrentHwProfile_Hook),
            this);
        /*
        var regGetValueHookA = EasyHook.LocalHook.Create(
            EasyHook.LocalHook.GetProcAddress("kernelbase.dll", "RegGetValueA"),
            new RegGetValue_Delegate(RegGetValue_Hook),
            this);*/

        var getSystemFirmwareTableHook = LocalHook.Create(
            LocalHook.GetProcAddress("kernel32.dll", "GetSystemFirmwareTable"),
            new GetSystemFirmwareTableDelegate(GetSystemFirmwareTable_Hook),
            this);


        // Activate hooks on all threads except the current thread
        getVolumeInformationHookW.ThreadACL.SetExclusiveACL(new[] {0});
        getAdaptersInfoHook.ThreadACL.SetExclusiveACL(new[] {0});
        regGetValueHookW.ThreadACL.SetExclusiveACL(new[] {0});
        getVolumeInformationHookA.ThreadACL.SetExclusiveACL(new[] {0});
        getCurrentHwProfileHookW.ThreadACL.SetExclusiveACL(new[] {0});
        getCurrentHwProfileHookA.ThreadACL.SetExclusiveACL(new[] {0});
        //RegGetValueHookA.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
        getSystemFirmwareTableHook.ThreadACL.SetExclusiveACL(new[] {0});

        #region middle_1

        _server.ReportMessage("EasyHook hooks installed");

        // Wake up the process (required if using RemoteHooking.CreateAndInject)
        RemoteHooking.WakeUpProcess();

        try
        {
            // Loop until FileMonitor closes (i.e. IPC fails)
            while (true)
            {
                Thread.Sleep(500);

                string[] queued = null;

                lock (_messageQueue)
                {
                    queued = _messageQueue.ToArray();
                    _messageQueue.Clear();
                }

                // Send newly monitored file accesses to FileMonitor
                if (queued.Length > 0)
                    _server.ReportMessages(queued);
                else
                    _server.Ping();
            }
        }
        catch
        {
            // Ping() or ReportMessages() will raise an exception if host is unreachable
        }

        #endregion

        // Remove hooks
        getVolumeInformationHookW.Dispose();
        getAdaptersInfoHook.Dispose();
        regGetValueHookW.Dispose();
        getVolumeInformationHookA.Dispose();
        getCurrentHwProfileHookA.Dispose();
        getCurrentHwProfileHookW.Dispose();
        //RegGetValueHookA.Dispose();
        getSystemFirmwareTableHook.Dispose();

        #region middle_2

        // Finalise cleanup of hooks
        LocalHook.Release();
    }

    #endregion


    #region volume_info_hook

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetVolumeInformationDelegate(
        string rootPathName,
        StringBuilder volumeNameBuffer,
        int volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        StringBuilder fileSystemNameBuffer,
        int nFileSystemNameSize);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern bool GetVolumeInformation(
        string rootPathName,
        StringBuilder volumeNameBuffer,
        int volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        StringBuilder fileSystemNameBuffer,
        int nFileSystemNameSize);

    private bool GetVolumeInformation_Hook(
        string rootPathName,
        StringBuilder volumeNameBuffer,
        int volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        StringBuilder fileSystemNameBuffer,
        int nFileSystemNameSize)
    {
        var result = false;
        var rd = new Random();
        result = GetVolumeInformation(
            rootPathName,
            volumeNameBuffer,
            volumeNameSize,
            out volumeSerialNumber,
            out maximumComponentLength,
            out fileSystemFlags,
            fileSystemNameBuffer,
            nFileSystemNameSize);
        var oldSerial = volumeSerialNumber;
        volumeSerialNumber = (uint) rd.Next(1000000000, 2099999999);
        //fileSystemFlags = (uint)rd.Next(10000000, 90000000);
        _server.ReportMessage("Old Serial: " + oldSerial + "    New Serial: " + volumeSerialNumber);
        return result;
    }

    #endregion


    #region adapter_info_hook

    #region mac_address_defines
    public class IpHlpConstants
    {
        public const Int32 MAX_ADAPTER_NAME = 128;
        public const Int32 MAX_ADAPTER_NAME_LENGTH = 256;
        public const Int32 MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
        public const Int32 MAX_ADAPTER_ADDRESS_LENGTH = 8;
        public const UInt32 ERROR_BUFFER_OVERFLOW = (UInt32)111;
        public const Int32 ERROR_SUCCESS = 0;
        public const int MIB_IF_TYPE_ETHERNET = 6;
        public const int MIB_IF_TYPE_TOKENRING = 9;
        public const int MIB_IF_TYPE_FDDI = 15;
        public const int MIB_IF_TYPE_PPP = 23;
        public const int MIB_IF_TYPE_LOOPBACK = 24;
        public const int MIB_IF_TYPE_SLIP = 28;
        public const int MIB_IF_TYPE_OTHER = 1;
    }

    /// <summary>
    /// IP_ADDRESS_STRING - http://msdn2.microsoft.com/en-us/library/aa366067.aspx
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public class IP_ADDRESS_STRING
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string address;
    };

    /// <summary>
    /// IP_MASK_STRING - a clone of IP_ADDRESS_STRING used for retrieving subnet masks.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public class IP_MASK_STRING
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string address;
    };


    /// <summary>
    /// IP_ADDR_STRING - http://msdn2.microsoft.com/en-us/library/aa366068.aspx
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public class IP_ADDR_STRING
    {
        public int Next;      /* struct _IP_ADDR_STRING* */
        public IP_ADDRESS_STRING IpAddress;
        public IP_MASK_STRING IpMask;
        public uint Context;
    }


    /// <summary>
    /// IP_ADAPTER_INFO - http://msdn2.microsoft.com/en-us/library/aa366062.aspx
    /// I have added _LEGACY to indicate that it is being deprecated by the IP_ADAPTER_ADDRESSES structure starting from Windows XP 
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public class IP_ADAPTER_INFO
    {
        public IntPtr Next;
        public uint ComboIndex;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = (IpHlpConstants.MAX_ADAPTER_NAME_LENGTH + 4))]
        public String AdapterName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = IpHlpConstants.MAX_ADAPTER_DESCRIPTION_LENGTH + 4)]
        public String Description;
        public int AddressLength;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = IpHlpConstants.MAX_ADAPTER_ADDRESS_LENGTH)]
        public byte[] Address;
        public int Index;
        public int Type;
        public int DhcpEnabled;
        public uint CurrentIpAddress; /* RESERVED */
        public IP_ADDR_STRING IpAddressList;
        public IP_ADDR_STRING GatewayList;
        public IP_ADDR_STRING DhcpServer;
        [MarshalAs(UnmanagedType.Bool)]
        public bool HaveWins;
        public IP_ADDR_STRING PrimaryWinsServer;
        public IP_ADDR_STRING SecondaryWinsServer;
        public uint/*time_t*/ LeaseObtained;
        public uint/*time_t*/ LeaseExpires;
    }

    #endregion

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int GetAdaptersInfoDelegate(IntPtr adaptersInfo, ref long bufferSize);

    [DllImport("iphlpapi.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int GetAdaptersInfo(IntPtr adaptersInfo, ref long bufferSize);

    private int GetAdaptersInfo_Hook(IntPtr adaptersInfo, ref long bufferSize)
    {
        var rd = new Random();
        var result = (int) IpHlpConstants.ERROR_BUFFER_OVERFLOW;
        result = GetAdaptersInfo(adaptersInfo, ref bufferSize);

        if (result == 0)
        {
            var pEntry = adaptersInfo;
            do
            {
                var entry = (IP_ADAPTER_INFO) Marshal.PtrToStructure(pEntry, typeof(IP_ADAPTER_INFO));
                var g = Guid.NewGuid();
                var guid = string.Concat("{", g, "}");
                entry.AdapterName = guid;
                _server.ReportMessage(entry.Description + " New Guid: " + guid);
                var macAddress = new StringBuilder();
                for (var i = 0; i < entry.Address.Length - 2; i++)
                {
                    var number = rd.Next(0, 255);
                    var b = Convert.ToByte(number);
                    macAddress.AppendFormat("{0:x2}:".ToUpper(), b);
                    entry.Address[i] = b;
                }
                var macAddressString = macAddress.ToString().Substring(0, macAddress.ToString().Length - 1);
                _server.ReportMessage(entry.Description + " New Mac Address: " + macAddressString);
                Marshal.StructureToPtr(entry, pEntry, false);

                pEntry = entry.Next;
            } while (pEntry != IntPtr.Zero);
        }

        return result;
    }

    #endregion


    #region reg_get_value_hook

    private enum Hkey : uint
    {
        HKEY_CLASSES_ROOT = 0x80000000,
        HKEY_CURRENT_USER = 0x80000001,
        HKEY_LOCAL_MACHINE = 0x80000002,
        HKEY_USERS = 0x80000003,
        HKEY_PERFORMANCE_DATA = 0x80000004,
        HKEY_CURRENT_CONFIG = 0x80000005,
        HKEY_DYN_DATA = 0x80000006
    }

    private enum RType
    {
        REG_NONE = 0,
        REG_SZ = 1,
        REG_EXPAND_SZ = 2,
        REG_MULTI_SZ = 7,
        REG_BINARY = 3,
        REG_DWORD = 4,
        REG_QWORD = 11,
        REG_QWORD_LITTLE_ENDIAN = 11,
        REG_DWORD_LITTLE_ENDIAN = 4,
        REG_DWORD_BIG_ENDIAN = 5,
        REG_LINK = 6,
        REG_RESOURCE_LIST = 8,
        REG_FULL_RESOURCE_DESCRIPTOR = 9,
        REG_RESOURCE_REQUIREMENTS_LIST = 10
    }

    private enum RFlags
    {
        ANY = 65535,
        REG_NONE = 1,
        NOEXPAND = 268435456,
        REG_BINARY = 8,
        DWORD = 24,
        REG_DWORD = 16,
        QWORD = 72,
        REG_QWORD = 64,
        REG_SZ = 2,
        REG_MULTI_SZ = 32,
        REG_EXPAND_SZ = 4,
        RRF_ZEROONFAILURE = 536870912
    }


    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int RegGetValueDelegate(
        Hkey hKey,
        IntPtr subKey,
        IntPtr value,
        RFlags flags,
        out RType type,
        IntPtr vData,
        ref int pData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        CallingConvention = CallingConvention.StdCall)]
    private static extern int RegGetValueW(
        Hkey hkey,
        IntPtr lpSubKey,
        IntPtr lpValue,
        RFlags dwFlags,
        out RType pdwType,
        IntPtr pvData,
        ref int pcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true,
        CallingConvention = CallingConvention.StdCall)]
    private static extern int RegGetValueA(
        Hkey hkey,
        IntPtr lpSubKey,
        IntPtr lpValue,
        RFlags dwFlags,
        out RType pdwType,
        IntPtr pvData,
        ref int pcbData);

    private int RegGetValue_Hook(
        Hkey hkey,
        IntPtr lpSubKey,
        IntPtr lpValue,
        RFlags dwFlags,
        out RType pdwType,
        IntPtr pvData,
        ref int pcbData)
    {
        var valueName = Marshal.PtrToStringAuto(lpValue);
        //_server.ReportMessage("Value: " + valueName);
        var keyName = Marshal.PtrToStringAuto(lpSubKey);
        //_server.ReportMessage("Key: " + keyName);
        var retVal = 0;
        switch (valueName)
        {
            case "SusClientId":
            {
                var g = Guid.NewGuid();
                var registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                registryKey.SetValue("RandomSz", g);
                registryKey.Close();
                _server.ReportMessage("New " + valueName + ": " + g);
                retVal = RegGetValueW(Hkey.HKEY_LOCAL_MACHINE, Marshal.StringToHGlobalAuto("SOFTWARE"),
                    Marshal.StringToHGlobalAuto("RandomSz"), RFlags.REG_SZ, out pdwType, pvData, ref pcbData);
                return retVal;
            }
            case "ProductId":
            {
                var r = new Random();
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                var x1 = new string(Enumerable.Repeat(chars, 5).Select(s => s[r.Next(s.Length)]).ToArray());
                var x2 = new string(Enumerable.Repeat(chars, 5).Select(s => s[r.Next(s.Length)]).ToArray());
                var x3 = new string(Enumerable.Repeat(chars, 5).Select(s => s[r.Next(s.Length)]).ToArray());
                var x4 = new string(Enumerable.Repeat(chars, 5).Select(s => s[r.Next(s.Length)]).ToArray());
                var id = x1 + "-" + x2 + "-" + x3 + "-" + x4;
                var registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                registryKey.SetValue("RandomSz", id);
                registryKey.Close();
                _server.ReportMessage("New " + valueName + ": " + id);
                retVal = RegGetValueA(Hkey.HKEY_LOCAL_MACHINE, Marshal.StringToHGlobalAuto("SOFTWARE"),
                    Marshal.StringToHGlobalAuto("RandomSz"), RFlags.REG_SZ, out pdwType, pvData, ref pcbData);
                return retVal;
            }
            case "InstallDate":
            {
                var r = new Random();
                var date = r.Next(1000000000, 1600000000);
                var registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                registryKey.SetValue("RandomSz", date);
                registryKey.Close();
                _server.ReportMessage("New " + valueName + ": " + date);
                retVal = RegGetValueA(Hkey.HKEY_LOCAL_MACHINE, Marshal.StringToHGlobalAuto("SOFTWARE"),
                    Marshal.StringToHGlobalAuto("RandomSz"), RFlags.REG_SZ, out pdwType, pvData, ref pcbData);
                return retVal;
            }
            case "RegisteredOwner":
            {
                var r = new Random();
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                var owner = new string(Enumerable.Repeat(chars, 8).Select(s => s[r.Next(s.Length)]).ToArray());
                var registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                registryKey.SetValue("RandomSz", owner);
                registryKey.Close();
                _server.ReportMessage("New " + valueName + ": " + owner);
                retVal = RegGetValueA(Hkey.HKEY_LOCAL_MACHINE, Marshal.StringToHGlobalAuto("SOFTWARE"),
                    Marshal.StringToHGlobalAuto("RandomSz"), RFlags.REG_SZ, out pdwType, pvData, ref pcbData);
                return retVal;
            }
            case "MachineGuid":
            {
                var g = Guid.NewGuid();
                var registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                registryKey.SetValue("RandomSz", g);
                registryKey.Close();
                _server.ReportMessage("New " + valueName + ": " + g);
                retVal = RegGetValueW(Hkey.HKEY_LOCAL_MACHINE, Marshal.StringToHGlobalAuto("SOFTWARE"),
                    Marshal.StringToHGlobalAuto("RandomSz"), RFlags.REG_SZ, out pdwType, pvData, ref pcbData);
                return retVal;
            }
            default:
            {
                var r = new Random();
                var registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                var rndStr = new string(Enumerable.Repeat(chars, r.Next(15, 45)).Select(s => s[r.Next(s.Length)])
                    .ToArray());
                registryKey.SetValue("RandomSz", rndStr);
                registryKey.Close();
                _server.ReportMessage("New " + valueName + ": " + rndStr);
                retVal = RegGetValueA(Hkey.HKEY_LOCAL_MACHINE, Marshal.StringToHGlobalAuto("SOFTWARE"),
                    Marshal.StringToHGlobalAuto("RandomSz"), RFlags.REG_SZ, out pdwType, pvData, ref pcbData);
                return retVal;
            }
        }
    }

    #endregion


    #region hwprofile_hook

    [StructLayout(LayoutKind.Sequential)]
    private class HwProfileInfo
    {
        [MarshalAs(UnmanagedType.U4)] public int dwDockInfo;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 39)]
        public string szHwProfileGuid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szHwProfileName;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetCurrentHwProfileDelegate(IntPtr fProfile);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetCurrentHwProfile(IntPtr fProfile);

    private bool GetCurrentHwProfile_Hook(IntPtr fProfile)
    {
        var profile = new HwProfileInfo();
        var profilePtr = Marshal.AllocHGlobal(Marshal.SizeOf(profile));
        //var result = GetCurrentHwProfile(profilePtr);
        Marshal.PtrToStructure(profilePtr, profile);
        var g = Guid.NewGuid();
        profile.szHwProfileGuid = string.Concat("{", g.ToString(), "}");
        _server.ReportMessage("New HwProfileId: " + profile.szHwProfileGuid);
        Marshal.StructureToPtr(profile, fProfile, false);
        return true;
    }
    #endregion


    #region get_system_firmware_table

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetSystemFirmwareTableDelegate();

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern bool GetSystemFirmwareTable();

    private bool GetSystemFirmwareTable_Hook()
    {
        _server.ReportMessage("GetSystemFirmwareTable hooked");
        return false;
    }

    #endregion
}