#!/bin/bash 
 
# Defining the target IP address 
target="10.0.2.5" 
 
# Defining port range  
port_range="100-1000" 
 
# Nmap scan  
echo "Running Nmap scan on target $target..." 
nmap_result=$(nmap "$target") echo "Nmap scan result:" 
echo "$nmap_result" 
 
# Netcat scan  
echo "Running Netcat on target $target..." 
netcat_result=$(nc -v -n -z -w1 "$target" "$port_range") 
echo "Netcat result for $target" 
echo "$netcat_result"
