package io.pkts.streams;

import io.pkts.Pcap;
import io.pkts.frame.PcapGlobalHeader;
import io.pkts.packet.Packet;
import io.pkts.packet.PacketParseException;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;
import io.pkts.streams.impl.tcpFSM.TcpStreamFSM;
import org.junit.After;
import org.junit.Test;
import io.pkts.streams.impl.TransportStreamId;
import io.pkts.streams.impl.DefaultTcpStream;

import java.io.IOException;

import static org.junit.Assert.*;

/**
 * Simple unit tests for objects used for implementing tcp streams
 *
 * @author sebastien.amelinckx@gmail.com
 */
public class TcpStreamTest {
    TransportStreamId id;
    TcpStream stream;

    @After
    public void tearDown(){
        id = null;
        stream = null;
    }

    @Test
    public void basicTcpStreamTest() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-fsm/tcp_established_small.pcap"));
            pcap.loop(packet -> {
                if (packet.hasProtocol(Protocol.TCP)){
                    TCPPacket TcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);

                    if(id == null){
                        id = new TransportStreamId(TcpPacket);
                        stream = new DefaultTcpStream(assignGlobalHeader(TcpPacket.getParentPacket().getParentPacket()), id, 1, null);
                    }
                    stream.addPacket(TcpPacket);
                }
                return true;
            });
        } catch (IOException e) {
            e.printStackTrace();
            fail("Failed to open pcap file");
        }

        assertEquals(stream.getStreamIdentifier(), id);
        assertEquals(stream.getState(), TcpStreamFSM.TcpState.ESTABLISHED);
        assertFalse(stream.ended());

        assertEquals(stream.getSrcAddr(), "172.16.100.13");
        assertEquals(stream.getDestAddr(), "172.16.100.10");
        assertEquals(stream.getSrcPort(), 2436);
        assertEquals(stream.getDestPort(), 389);
        assertEquals(stream.getUuid(), 1);

    }


    private static PcapGlobalHeader assignGlobalHeader(Packet frame) throws PacketParseException {
        PcapGlobalHeader header = null;
        try {
            if (frame.hasProtocol(Protocol.SLL)) {
                header = PcapGlobalHeader.createDefaultHeader(Protocol.SLL);
            } else if (frame.hasProtocol(Protocol.ETHERNET_II)) {
                header = PcapGlobalHeader.createDefaultHeader(Protocol.ETHERNET_II);
            } else {
                throw new PacketParseException(0, "Unable to create the PcapGlobalHeader because the "
                        + "link type isn't recognized. Currently only Ethernet II "
                        + "and Linux SLL (linux cooked capture) are implemented");
            }

        } catch (IOException e){
            e.printStackTrace();
        }
        return header;
    }
}
