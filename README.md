# ReadMe

Simple port scanner written for the internet security class at university. It is able to do "connect" and "SYN" scans on a host. Run as root to gain access to the low-level network interface APIs.


## Arguments


 -attack VAL    : 'connect' or 'syn'  
 -end N         : The upper bound of a range of ports that will be tested.  
 -help          : Shows an overview of all available commands.  
 -host VAL      : A valid URL or IP address that will be scanned  
 -interface VAL : A network interface used for port scanning. If unsure use '-list'.  
 -list          : List all available network interfaces of your computer.  
 -start N       : The lower bound of a range of ports that will be tested.  


## Example

sudo su
java -jar ./PortScanner.jar -host localhost -start 0 -end 65535 -interface lo  
  
No attack method specified. Using 'connect' attack.  
Scanning localhost/127.0.0.1... (This may take a while!)  
Port 22 is open.  
Port 53 is open.    
Port 631 is open.  
Port 1337 is open.  
Port 40853 is open.  
Scanning ports 0 - 65535 is done!  


## Build

There is an ant build file included that produces a JAR file in the project root. It also includes the dependency library "args4j".


## Dependencies


arg4j  
https://github.com/kohsuke/args4j  

Jpcap  
http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/  


## Disclaimer

This tool is strictly for scientific purposes. I wrote this a port of an internet security class at university. No one is encourage to use this to cause damage. I can not be held responsible for any damage you may do.
