package de.unipotsdam.hpi;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class SynPacketReceiver implements PacketReceiver {

	 
	 @Override
	 public void receivePacket(Packet packet){
		 
		 if (packet instanceof TCPPacket)
		 {
			 //if a packages has gotte through the filtern the repsonse contains a port
			 TCPPacket tcp = (TCPPacket) packet;
			 
			 //System.out.format("Port %d - ACK %b - SYN %b - RST %b %n", tcp.src_port, tcp.ack ,tcp.syn, tcp.rst);
			 
			 if (tcp.ack && tcp.syn)
				 System.out.format("Port %d is open. %n",tcp.src_port);
		 }
		 
	 }
}