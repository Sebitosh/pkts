package io.pkts.streams.impl;

import io.hektor.fsm.FSM;
import io.pkts.Pcap;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;
import io.pkts.streams.StreamsTestBase;
import io.pkts.streams.impl.tcpFSM.TcpStreamContext;
import io.pkts.streams.impl.tcpFSM.TcpStreamData;
import io.pkts.streams.impl.tcpFSM.TcpStreamFSM;
import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import java.util.ArrayList;

/**
 * Unit tests for the {@link TcpStreamFSM}.
 *
 * @author sebastien.amelinckx@gmail.com
 */
public class TcpStreamFSMTest {

    FSM stream;
    TcpStreamContext ctx;
    TcpStreamData data;
    ArrayList<TCPPacket> packets;

    @Before
    public void setUp(){
        ctx = new TcpStreamContext();
        data = new TcpStreamData();
        stream = TcpStreamFSM.definition.newInstance("uuid-123",ctx, data);
        stream.start();
    }


    @Test
    public void testFewEstablishedOnly() {
        packets = retrievePackets("tcp-fsm/tcp_established_small.pcap");
        assertEquals(TcpStreamFSM.TcpState.INIT, stream.getState());
        for (TCPPacket packet : packets) {
            stream.onEvent(packet);
            assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());
        }
    }

    @Test
    public void testEstablishedOnly() {
        packets = retrievePackets("tcp-fsm/tcp_nosyn_nofin_norst.pcap");
        assertEquals(TcpStreamFSM.TcpState.INIT, stream.getState());
        for (TCPPacket packet : packets) {
            stream.onEvent(packet);
            assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());
        }
    }

    @Test
    public void testFinEndStandard() {
        packets = retrievePackets("tcp-fsm/tcp_graceful_fin1_fin2.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        packets.remove(0);
        packets.remove(0);

        // process established connection until start of gracefull end
        int count = 0;
        for (TCPPacket packet : packets) {
            count++;
            stream.onEvent(packet);
            if (stream.getState() != TcpStreamFSM.TcpState.ESTABLISHED){
                assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());
                break;
            }
        }

        stream.onEvent(packets.get(count));
        assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_2, stream.getState());

        stream.onEvent(packets.get(++count));
        assertEquals(TcpStreamFSM.TcpState.CLOSED_1_CLOSING_2, stream.getState());

        stream.onEvent(packets.get(++count));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());

    }

    @Test
    public void testFinEndFinAndAckOfFin1() {
        packets = retrievePackets("tcp-fsm/tcp_fin_ack.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        packets.remove(0);
        packets.remove(0);

        // process established connection until start of gracefull end
        int count = 0;
        for (TCPPacket packet : packets) {
            count++;
            stream.onEvent(packet);
            if (stream.getState() != TcpStreamFSM.TcpState.ESTABLISHED){
                assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());
                break;
            }
        }

        stream.onEvent(packets.get(count)); // case FIN + ACK of first FIN
        assertEquals(TcpStreamFSM.TcpState.CLOSED_1_CLOSING_2, stream.getState());

        stream.onEvent(packets.get(++count));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());
    }


    @Test
    public void testFinEndSimultanuousClosing() {
        packets = retrievePackets("tcp-fsm/tcp_fin_simult.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        packets.remove(0);
        packets.remove(0);

        // process established connection until graceful end
        int count = 0;
        for (TCPPacket packet : packets) {
            count++;
            stream.onEvent(packet);
            if (stream.getState() != TcpStreamFSM.TcpState.ESTABLISHED){
                assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());
                break;
            }
        }

        stream.onEvent(packets.get(count));
        assertEquals(TcpStreamFSM.TcpState.CLOSING_1_CLOSING_2, stream.getState());

        stream.onEvent(packets.get(++count));
        assertEquals(TcpStreamFSM.TcpState.CLOSING_1_CLOSED_2, stream.getState());

        stream.onEvent(packets.get(++count));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());
    }

    @Test
    public void testRstEndInit() {
        packets = retrievePackets("tcp-fsm/tcp_init_rst.pcap");

        assertEquals(TcpStreamFSM.TcpState.INIT, stream.getState());
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());
    }

    @Test
    public void testRstEndHanshake() {
        packets = retrievePackets("tcp-fsm/tcp_handshake_rst.pcap");

        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(2));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());
    }

    @Test
    public void testRstEndEstablished() {
        packets = retrievePackets("tcp-fsm/tcp_established_rst.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        packets.remove(0);
        packets.remove(0);

        // process established connection until abrupt end
        for (TCPPacket packet : packets) {
            stream.onEvent(packet);
            if (stream.getState() != TcpStreamFSM.TcpState.ESTABLISHED){
                assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());
                break;
            }
        }
    }

    @Test
    public void testRstEndFinWait1() {
        packets = retrievePackets("tcp-fsm/tcp_fin1_rst.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        packets.remove(0);
        packets.remove(0);

        // process established connection until graceful end
        int count = 0;
        for (TCPPacket packet : packets) {
            count++;
            stream.onEvent(packet);
            if (stream.getState() != TcpStreamFSM.TcpState.ESTABLISHED){
                assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());
                break;
            }
        }
        // abrupt end in FIN_WAIT_1
        stream.onEvent(packets.get(count));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());

    }

    @Test
    public void testRstEndFinWait2() {
        packets = retrievePackets("tcp-fsm/tcp_closed1_rst2.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        packets.remove(0);
        packets.remove(0);

        // process established connection until graceful end
        int count = 0;
        for (TCPPacket packet : packets) {
            count++;
            stream.onEvent(packet);
            if (stream.getState() != TcpStreamFSM.TcpState.ESTABLISHED){
                assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());
                break;
            }
        }

        stream.onEvent(packets.get(count));
        assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_2, stream.getState());

        // abrupt end in FIN_WAIT_2
        stream.onEvent(packets.get(++count));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());

    }

    // fails because the new SYN is a duplicate (also marked in wireshark)
    @Test
    public void testSynEndEstablished() {
        packets = retrievePackets("tcp-fsm/tcp_established_syn.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(2));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());

        // syn packet but it is a duplicate, should have no effect on the FSM state
        stream.onEvent(packets.get(3));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());

    }

    // fails because the new SYN is a duplicate (also marked in wireshark)
    @Test
    public void testSynEndFin1() {
        packets = retrievePackets("tcp-fsm/tcp_fin1_syn.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(2));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());
        stream.onEvent(packets.get(3));
        assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());

        // syn packet but it is a duplicate, should have no effect on the FSM state
        stream.onEvent(packets.get(4));
        assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());

    }


    @Test
    public void testEstablishedSynPortsReused() {
        packets = retrievePackets("tcp-fsm/established_syn_ports_reused.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(2));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());

        // 3 data packets
        stream.onEvent(packets.get(3));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());
        stream.onEvent(packets.get(4));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());
        stream.onEvent(packets.get(5));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());

        // new syn reusing ports (marked in wireshark), FSM should consider the connection closed
        stream.onEvent(packets.get(6));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());

    }

    @Test
    public void testFin1SynPortsReused() {
        packets = retrievePackets("tcp-fsm/fin1_syn_ports_reused.pcap");

        // syn exchange
        stream.onEvent(packets.get(0));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(1));
        assertEquals(TcpStreamFSM.TcpState.HANDSHAKE, stream.getState());
        stream.onEvent(packets.get(2));
        assertEquals(TcpStreamFSM.TcpState.ESTABLISHED, stream.getState());
        stream.onEvent(packets.get(3));
        assertEquals(TcpStreamFSM.TcpState.FIN_WAIT_1, stream.getState());

        // new syn reusing ports (marked in wireshark), FSM should consider the connection closed
        stream.onEvent(packets.get(4));
        assertEquals(TcpStreamFSM.TcpState.CLOSED, stream.getState());

    }



    private static ArrayList<TCPPacket> retrievePackets(String filename){
        ArrayList<TCPPacket> packets = new ArrayList<>();
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream(filename));
            pcap.loop(packet -> {
                if (packet.hasProtocol(Protocol.TCP)) {
                    packets.add((TCPPacket) packet.getPacket(Protocol.TCP));
                }
                return true;
            });

        } catch (Exception e) {
            e.printStackTrace();
        }
        return packets;
    }

}
