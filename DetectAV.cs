using System;
using System.Collections.Generic; // Used for HashSet
using System.ComponentModel;      // Used for Win32Exception
using System.Diagnostics;
using System.IO;
using System.Management;

internal class Program
{
    static void Main(string[] args)
    {
        // This HashSet will store the names of found AVs to avoid duplicate reports
        var foundAVs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Console.WriteLine("[+] Antivirus check is running .. ");
        Console.WriteLine("[!] Note: This program must be 'Run as Administrator' to detect AVs running as SYSTEM.");

        // Load the AV list
        var avCheck = LoadAVList();

        // If avCheck is empty after trying to load, we can't proceed.
        if (avCheck.Count == 0)
        {
            Console.WriteLine("[Error] AV list is empty. Cannot perform check.");
            return;
        }

        // Method 1: Use Process API
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string procName = proc.ProcessName + ".exe";
                    if (avCheck.Contains(procName))
                    {
                        foundAVs.Add(procName);
                    }
                }
                // This can happen if the process exits right as we try to access it
                catch (InvalidOperationException) 
                { 
                    continue; 
                } 
                // This can happen for high-privilege processes (like AVs)
                // if the program is NOT run as administrator.
                catch (Win32Exception) 
                { 
                    continue; 
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] Failed to query processes with .NET API: {ex.Message}");
        }


        // Method 2: Use WMI for redundancy
        try
        {
            var searcher = new ManagementObjectSearcher("select Name from Win32_Process");
            foreach (var process in searcher.Get())
            {
                try
                {
                    string name = process["Name"]?.ToString();
                    if (!string.IsNullOrEmpty(name) && avCheck.Contains(name))
                    {
                        foundAVs.Add(name);
                    }
                }
                catch (Exception)
                {
                    continue; // Ignore individual process query failures
                }
            }
        }
        catch (ManagementException ex)
        {
            Console.WriteLine($"[Error] Failed to query WMI: {ex.Message}. (Is WMI service running?)");
        }

        // --- Final Report ---
        if (foundAVs.Count > 0)
        {
            Console.WriteLine("\n[+] Found {0} AV-related process(es):", foundAVs.Count);
            foreach (var av in foundAVs)
            {
                Console.WriteLine($"  -- {av}");
            }
        }
        else
        {
            Console.WriteLine("\n[+] No AV software from the list was found.");
            Console.WriteLine("[!] (This does NOT guarantee no AV is present. See administrator note.)");
        }
    }

    /// <summary>
    /// Loads the AV list from the default array, then tries to 
    /// overwrite it with the av_list.txt file if it exists and is not empty.
    /// </summary>
    /// <returns>A HashSet of AV process names.</returns>
    private static HashSet<string> LoadAVList()
    {
        // Start with the default list.
        var defaultList = new string[] {
            "MsMpEng.exe", "AdAwareService.exe", "afwServ.exe", "avguard.exe", "AVGSvc.exe",
            "bdagent.exe", "BullGuardCore.exe", "ekrn.exe", "fshoster32.exe", "GDScan.exe",
            "avp.exe", "K7CrvSvc.exe", "McAPExe.exe", "NortonSecurity.exe", "PavFnSvr.exe",
            "SavService.exe", "EnterpriseService.exe", "WRSA.exe", "ZAPrivacyService.exe"
        };
        
        // Use a HashSet for fast lookups (O(1) average)
        var avList = new HashSet<string>(defaultList, StringComparer.OrdinalIgnoreCase);

        try
        {
            if (File.Exists("av_list.txt"))
            {
                var lines = File.ReadAllLines("av_list.txt");
                
                // BUG FIX: Only replace the default list if the file
                // actually contains data.
                if (lines.Length > 0)
                {
                    avList = new HashSet<string>(lines, StringComparer.OrdinalIgnoreCase);
                    Console.WriteLine("[+] Loaded {0} AV signatures from av_list.txt", avList.Count);
                }
                else
                {
                    Console.WriteLine("[Info] av_list.txt was found but is empty. Using default list.");
                }
            }
            else
            {
                Console.WriteLine("[Info] av_list.txt not found. Using default list.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] Could not read av_list.txt: {ex.Message}. Using default list.");
        }

        return avList;
    }
}
