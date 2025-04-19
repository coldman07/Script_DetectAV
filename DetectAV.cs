using System;
using System.Diagnostics;
using System.IO;
using System.Management;

internal class Program
{
    static void Main(string[] args)
    {
        bool status = false;
        Console.WriteLine("[+] Antivirus check is running .. ");

        // Load AV process names from external file if exists, fallback to default
        string[] AV_Check;
        if (File.Exists("av_list.txt"))
        {
            AV_Check = File.ReadAllLines("av_list.txt");
        }
        else
        {
            AV_Check = new string[] {
                "MsMpEng.exe", "AdAwareService.exe", "afwServ.exe", "avguard.exe", "AVGSvc.exe",
                "bdagent.exe", "BullGuardCore.exe", "ekrn.exe", "fshoster32.exe", "GDScan.exe",
                "avp.exe", "K7CrvSvc.exe", "McAPExe.exe", "NortonSecurity.exe", "PavFnSvr.exe",
                "SavService.exe", "EnterpriseService.exe", "WRSA.exe", "ZAPrivacyService.exe"
            };
        }

        // Method 1: Use Process API
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                string procName = proc.ProcessName + ".exe";
                if (Array.Exists(AV_Check, av => av.Equals(procName, StringComparison.OrdinalIgnoreCase)))
                {
                    Console.WriteLine("--AV Found (Process API): {0}", procName);
                    status = true;
                }
            }
            catch { continue; }
        }

        // Method 2: Use WMI for redundancy
        var searcher = new ManagementObjectSearcher("select * from Win32_Process");
        foreach (var process in searcher.Get())
        {
            try
            {
                string name = process["Name"].ToString();
                if (Array.Exists(AV_Check, av => av.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    Console.WriteLine("--AV Found (WMI): {0}", name);
                    status = true;
                }
            }
            catch { continue; }
        }

        if (!status)
        {
            Console.WriteLine("--AV software is not found!");
        }
    }
}
