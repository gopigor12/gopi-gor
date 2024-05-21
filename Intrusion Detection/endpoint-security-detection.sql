/* This attack type uses Microsoft Windows Defender. A vulnerability in the MS Defender leads an attacker to 
perform an elevation of privilege to access the system. The attacker depends on the user to give input in 
order to exploit the vulnerability. The exploitation is done via local access like a malicious link to the user or 
via SSH on console. The attacker path is read through read, write, or execute capabilities. */

_sourceCategory=Labs/Windows/OS/Windows 
| where eventid == "4688"   
| where ProcessCommandLine contains "exploit.exe" or ProcessCommandLine contains "exploit.bat"  
or ProcessCommandLine contains "exploit.cmd" 
| where ProcessCommandLine contains "SSH" or ProcessCommandLine contains "ssh" or 
ProcessCommandLine contains "powershell.exe" or ProcessCommandLine contains "cmd.exe"  

/* First, we select the source category as the log source we want to use in this query. Now in this case, we want 
to know if any process has been created  and thus, we use the eventid = 4688 which stands for new process 
creation.  The next line filters the process creation events where the process command line has common 
exploit files names like .exe, .bat, .cmd. The last line again filters for events that contain SSH  or PowerShell 
command like activity which could show the process creation events leading to exploitation.  
So overall, if we look at this query, it looks for process creation events, and then filters them in windows 
defender logs for the file types that exploits usually use and then filters it finally on the basis of the files types 
that run exploits. */
