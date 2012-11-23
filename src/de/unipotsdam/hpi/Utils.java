package de.unipotsdam.hpi;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Arrays;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;

public  class Utils {
	
	 	/**
 	 * Returns the IP address of the selected network interface.
 	 * @param networkInterface The network device to retrieve the IP from.
 	 * @return IP Address
 	 */
 	public static byte[] getIPAddress(NetworkInterface networkInterface)
 	{
	    // Extract local IP address
	    InetAddress localIPAddress = null;
	    for (NetworkInterfaceAddress addr : networkInterface.addresses) {
	        if (addr.address instanceof Inet4Address) {
	            localIPAddress = addr.address;
	            break;
	        }
	    }
	    
	    return localIPAddress.getAddress();
 	}
	 	
 	/**
 	 * Returns the MAC Address of a target host by sending an ARP request. Only works in a local network.
 	 * @param networkInterface The network device in charge of sending the ARP request.
 	 * @param hostAddress Address of target host.
 	 * @return MAC Address
 	 * @throws IOException
 	 */
 	public static String getMACAddress(NetworkInterface networkInterface, InetAddress hostAddress) throws IOException 
 	{

			// Build the ARP-Request packet
			ARPPacket arp_pack = Utils.buildArpRequestPacket(networkInterface,
					hostAddress);

			// Open Captor device and set read timeout
			JpcapCaptor captor = JpcapCaptor.openDevice(networkInterface, 2000,false, 2000);
			captor.setPacketReadTimeout(2500);

			// Open a sender device
			JpcapSender sender = captor.getJpcapSenderInstance();

			// Send ArpRequest
			sender.sendPacket(arp_pack);

			// Perform Arp Reply captor
			captor.setFilter("arp", true);
			while (true) {

				ARPPacket raw_pack = (ARPPacket) captor.getPacket();

				// Return NULL if not receive any response
				if (raw_pack == null)
					return null;

				if (Arrays.equals(raw_pack.target_protoaddr,
						Utils.getIPAddress(networkInterface))) {

					// This loop convert the Mac-Address from byte to String
					String macAddress = "";
					for (byte b : raw_pack.sender_hardaddr) {

						if (b == raw_pack.sender_hardaddr[raw_pack.sender_hardaddr.length - 1])
							macAddress += Integer.toHexString(b & 0xff);
						else
							macAddress += Integer.toHexString(b & 0xff) + ":";
					}

					// Return the mac-address in String format
					return macAddress;
				}
			}
		}

	/**
	 * Build an ARP request ready to be sent.
	 * @param networkInterface The network device in charge of sending the ARP request.
	 * @param hostAddress Address of target host.
	 * @return ARPPacket
	 */
	public static ARPPacket buildArpRequestPacket(NetworkInterface networkInterface, InetAddress hostAddress) 
	{

	    // Broadcast Mac Address
	    byte[] broadcast_mac_address = { (byte)255, (byte)255, (byte)255, (byte)255, (byte)255, (byte)255 };

	    // Create ARP Packet
	    ARPPacket arp = new ARPPacket();

	    arp.hardtype = ARPPacket.HARDTYPE_ETHER;
	    arp.prototype = ARPPacket.PROTOTYPE_IP;
	    arp.operation = ARPPacket.ARP_REQUEST;
	    arp.hlen=6;
	    arp.plen=4;

	    arp.sender_hardaddr = networkInterface.mac_address;
	    arp.sender_protoaddr = getIPAddress(networkInterface);

	    arp.target_hardaddr = broadcast_mac_address;
	    arp.target_protoaddr = hostAddress.getAddress();

	    // Set Ethernet frame
	    EthernetPacket ethernet = new EthernetPacket();
	    ethernet.frametype = EthernetPacket.ETHERTYPE_ARP;
	    ethernet.src_mac = networkInterface.mac_address;
	    ethernet.dst_mac = broadcast_mac_address;

	    // Set the type of Datalink
	    arp.datalink = ethernet;

	    return arp;
	}
	
	
	/**
	 * Tries to find the mac address of your gateway (usually you router) by sending a ping to google.de and fetching the response
	 * @param networkInterface
	 * @param targetURL
	 * @return
	 * @throws IOException
	 */
	public static byte[] getMacAddress(NetworkInterface networkInterface, String targetURL) throws IOException
	{
		byte[] destMac = null;
		
		JpcapCaptor echoCaptor = JpcapCaptor.openDevice(networkInterface, 65535, false, 20);
		
		String filter = "dst host " + targetURL + " && src host " + InetAddress.getLocalHost().getHostAddress() + " && icmp||tcp";
		echoCaptor.setFilter(filter, true);
		
		
		InetAddress.getByName(targetURL).isReachable(4000);
		Packet icmp = echoCaptor.getPacket();
		
		if (icmp == null) {
			
			System.out.println("Waiting for ping to return...");
			
		} else if (Arrays.equals(((EthernetPacket) icmp.datalink).src_mac, networkInterface.mac_address)) {
			
			destMac = ((EthernetPacket) icmp.datalink).dst_mac;

		}	
	
		echoCaptor.close();
		
		return destMac;
	}	
	
	/**
	 * Suggest a network interface base on whether it has an IP address and is
	 * an ethernet device.
	 */
	public static NetworkInterface getNetworkInterface() 
	{
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();

		for (NetworkInterface device : devices) {
			// is ethernet device
			if (device.datalink_description.equals("Ethernet")) {
				// has an IP address
				if (device.addresses.length > 0) {
					return device;	
				}
			}
		}
		return null;	
		
	}
	
	public static NetworkInterface getNetworkInterfaceByName(String name)
	{
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		for (NetworkInterface device : devices) 
		{
			if (device.name.equals(name))
				return device;
		}
		
		System.err.format("Could not find the %s interface!%n", name);
		return null;
	}
	

}