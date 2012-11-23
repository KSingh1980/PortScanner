package de.unipotsdam.hpi;

import java.io.IOException;
import java.net.*;
import java.util.*;

import jpcap.*;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;

public class Scanner {
	
	private NetworkInterface networkInterface;
	private InetAddress targetAddress;
	private byte[] targetMac;

	/**
	 * Constructor for a new scanner. 
	 * @param networkInterface
	 * 		The network interface that will be used for scanning.
	 * @param hostName
	 * 		The URL to the target host.
	 * @throws UnknownHostException
	 */
	Scanner(NetworkInterface networkInterface, String hostName) throws UnknownHostException{
		this.networkInterface = networkInterface;
		
		//resolve the IP Address of the target & find its mac address with ICMP packet
		this.targetAddress = InetAddress.getByName(hostName);
		
		try {
			this.targetMac = Utils.getMacAddress(networkInterface, hostName);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Perform a port scan on a specified range of ports by utilizing the
	 * "connect scan" method.
	 * 
	 * @param startPort
	 *            The lower bound of a range of ports that will be tested.
	 * @param endPort
	 *            The upper bound of a range of parts that will be tested.
	 * @param hostName
	 *            A valid URL or IP Address to the targeted host.
	 * @throws UnknownHostException
	 */
	void TCPConnectScan(int startPort, int endPort) throws IOException{
		List<Integer> openPorts = new ArrayList<Integer>();

		System.out.format("Scanning %s... (This may take a while!) %n", this.targetAddress);

		Socket connection = null;
		boolean success = false;

		// loop every port and try to establish a connection
		for (int port = startPort; port <= endPort; port++) {

			try {
				connection = new Socket();
				connection.connect(new InetSocketAddress(this.targetAddress, port),
						1000);
				success = true;
			} catch (IOException e) {
				//System.err.println(e.getMessage());
				success = false;
				continue;
				
			} finally {
				connection.close();
			}

			// remember the open ports
			if (success) {
				openPorts.add(port);
				System.out.format("Port %d is open. %n", port);
			}

		}

		System.out.format("Scanning ports %d - %d is done!%n", startPort, endPort);

	}

	/**
	 * Perform a port scan on a specified range of ports by utilizing the
	 * "SYN scan" method.
	 * 
	 * @param startPort
	 *            The lower bound of a range of ports that will be tested.
	 * @param endPort
	 *            The upper bound of a range of parts that will be tested.
	 * @param hostName
	 *            A valid URL or IP Address to the targeted host.
	 * @throws UnknownHostException
	 */
	void TCPSYNScan(int startPort, int endPort) throws IOException {
		
		/**
		  1. step  
		     send SYN package
		  2. step 
		     listen to response to SYN package
		  3. step 
		     answer with RST package
		 */
		
		 //Initialize our network device and open it for receiving
		JpcapCaptor captor = JpcapCaptor.openDevice(networkInterface,2000,false,1000);
		
		String filter = "src host " + this.targetAddress.getHostAddress();
		captor.setFilter(filter ,true);	

		System.out.format("Scanning %s... (This may take a while!) %n", this.targetAddress);
		
		//send SYN packages
		for (int port = startPort; port <= endPort; port++) {
			sendTCPPacket(port);
		}
	

		//listen for all packets 
		captor.processPacket(endPort - startPort, new SynPacketReceiver());
		captor.close();
		
		
		System.out.format("Scanning ports %d - %d is done!%n", startPort, endPort);
	}

	/**
	 * Send a TCP packet over the wire...
	 * @param port
	 * 		Port on the target machine.
	 * @param hostAddress
	 * 		IP Address of target machine
	 * @param networkInterface
	 * 		networking device 
	 * @throws IOException
	 */
	void sendTCPPacket(int port) throws IOException {
		 
		 try {
		 		 
			 // initiate our sender instance of the network device	 
			 JpcapSender sender = JpcapSender.openDevice(networkInterface);
			 

			 TCPPacket p=new TCPPacket(4000, port, 0, 0, false, false, false, false, true, false, false, false, 1024, 0);
			 
			 // Set the IPv4 parameters of the TCPPacket	 
			 p.setIPv4Parameter(0, false, false, false, 0, false, false, false, 0, 0, 200, IPPacket.IPPROTO_TCP, InetAddress.getLocalHost(), this.targetAddress);
			 
			 // Set the data to send with the connection 
			 p.data="".getBytes();
			 
			 /* Initiate the EthernetPacke ether that will transport the
			 TCP packet and start to build the packet */			 
			 EthernetPacket ether = new EthernetPacket();
			 ether.frametype = EthernetPacket.ETHERTYPE_IP;
			 
			 ether.src_mac = this.networkInterface.mac_address;
			 ether.dst_mac = this.targetMac;

			 // Set the Data Link Layer of the IPpacket to the Ethernet packet
			 p.datalink = ether; 
			 
			 sender.sendPacket(p);
			 sender.close();
			 
			 
		 } catch (Exception e) {
			 
			 System.out.println(e);
			 
		 }


	}
}
