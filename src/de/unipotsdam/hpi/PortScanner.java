package de.unipotsdam.hpi;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import jpcap.*;


public class PortScanner {

	
	@Option(name="-start", usage="The lower bound of a range of ports that will be tested.")
	private int startPort;
	
	@Option(name="-end", usage="The upper bound of a range of ports that will be tested.")
	private int endPort;
	
	@Option(name="-attack", usage="'connect' or 'syn'")
	private String attack;
	
	@Option(name="-interface", usage="A network interface used for port scanning. If unsure use '-list'.")
	private String interfaceName;
	
	@Option(name="-host", usage="A valid URL or IP address that will be scanned")
	private String hostName;
	
	@Option(name="-list", usage="List all available network interfaces of your computer.")
	boolean listInterfaces;
	
	@Option(name="-help", usage="Shows an overview of all available commands.")
	boolean needHelp;
	
    @Argument
    private List<String> arguments = new ArrayList<String>();
    
    CmdLineParser parser;
	
	public static void main(String[] args) 
	{
		//we have to do this for the args4j lib...
		PortScanner ps= new PortScanner();
		ps.parseCommandLineArguments(args);
	}
	
	/**
	 * Parse the command line arguments using the args4j library.
	 * @param args
	 * 		Command line arguments.
	 */
	void parseCommandLineArguments(String[] args)
	{
		parser = new CmdLineParser(this);
        
        // if you have a wider console, you could increase the value;
        parser.setUsageWidth(80);

        try {

            parser.parseArgument(args);

            
        } catch( CmdLineException e ) {
            
            System.err.println(e.getMessage());
            // print the list of available options
            parser.printUsage(System.err);

            return;
        }
        
        this.executeCommandLines();
	}
	
	/**
	 * Start the scanning according to the command line arguments provided.
	 */
    void executeCommandLines(){   

        if (this.listInterfaces)
        {
        	this.printNetworkInterfaces();
        	return;
        }
        
        if (this.needHelp)
        {
        	System.out.println("Welcome to the simple port scanner. Please execute the programm as 'root' for low-level network interface access. ");
        	parser.printUsage(System.out);
        	return;
        }
        
        if (this.startPort < 0 || this.endPort > 65535)
        {
        	System.err.println("You can only specifiy ports in the range 0 - 65535!");
        	return;
        }
        
        if (this.hostName==null)
        {
        	System.err.println("No host for scanning was specified.");
        	return;
        }
        
        if (this.interfaceName==null)
        {
        	System.out.println("No network interface specfied. I am trying to guess one...");
        	this.interfaceName = Utils.getNetworkInterface().name;
        	System.out.format("Using %s ...%n", this.interfaceName);
        }
        
        if (this.attack==null)
        {
        	System.err.println("No attack method specified. Using 'connect' attack.");
        	this.attack = "connect";
        }
        	
        
        if (this.startPort >= 0 && this.endPort >= 0)
        {
        	this.startScan();
        }

	} 
    
    /**
     * Start a port scan.
     */
    void startScan()
    {
    	//try matching the interface provided via command line the an actual one
    	NetworkInterface iface =  Utils.getNetworkInterfaceByName(this.interfaceName);
    	if (iface == null)
    		return;
    	
    	Scanner scanner;
    	
		try {
			scanner = new Scanner(iface, this.hostName);
		} catch (UnknownHostException e) {
			System.out.format("Sorry, we could not resolve %s. Please make sure it is spelled correctly!! %n", hostName);
			return;  
		}
		
		try
		{
			if(this.attack.equals("connect"))
			{
				scanner.TCPConnectScan(this.startPort, this.endPort);
			} else if(this.attack.equals("syn")) {		
				scanner.TCPSYNScan(this.startPort, this.endPort);
			}
			
		} catch(IOException e) {
			System.err.println("Sorry. Something went terribly wrong. Please try again. Are you 'root'?");
		}
    	    		
    }
	
    /**
     * Prints an overview of all available network interfaces.
     */
	void printNetworkInterfaces()
	{
				
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();

		//for each network interface
		for (int i = 0; i < devices.length; i++) {
		  //print out its name and description
		  System.out.println(i+": "+devices[i].name + "(" + devices[i].description+")");

		  //print out its datalink name and description
		  System.out.println(" datalink: "+devices[i].datalink_name + "(" + devices[i].datalink_description+")");

		  
		  //print out its MAC address
		  System.out.print(" MAC address:");
		  for (byte b : devices[i].mac_address)
		    System.out.print(Integer.toHexString(b&0xff) + ":");
		  System.out.println();

		  //print out its IP address, subnet mask and broadcast address
		  for (NetworkInterfaceAddress a : devices[i].addresses)
		    System.out.println(" address:"+a.address + " " + a.subnet + " "+ a.broadcast);
		}
		
	}
	


}
