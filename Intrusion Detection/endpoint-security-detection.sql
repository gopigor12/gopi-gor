_sourceCategory=Labs/Windows/OS/Windows 
| where eventid == "4688"   
| where ProcessCommandLine contains "exploit.exe" or ProcessCommandLine contains "exploit.bat"  
or ProcessCommandLine contains "exploit.cmd" 
| where ProcessCommandLine contains "SSH" or ProcessCommandLine contains "ssh" or 
ProcessCommandLine contains "powershell.exe" or ProcessCommandLine contains "cmd.exe"  
