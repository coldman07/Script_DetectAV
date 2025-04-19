#🛡️ AV Detector Improved

This C# program identifies running antivirus software on a Windows system using two detection methods:

🧠 Process API

🔍 Windows Management Instrumentation (WMI)

🚀 Features

Dual-method scanning for better accuracy

Uses an external av_list.txt if available

Provides informative console output

📂 Files

Program.cs — The main C# detection script

av_list.txt (optional) — List of antivirus process names to match

⚙️ How to Use

🛠️ Compile the code:

csc Program.cs

▶️ Run the executable:

Program.exe

✅ View AV detection results in the console

📦 Example Output

[+] Antivirus check is running ..
--AV Found (Process API): MsMpEng.exe
--AV Found (WMI): MsMpEng.exe

📌 Notes

The tool is designed for educational and authorized testing use

Easily extensible for more advanced AV evasion or detection techniques

📝 License

MIT License — free to use, modify, and distribute.

