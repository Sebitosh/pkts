package io.pkts.streams.impl;

import io.pkts.Pcap;
import io.pkts.packet.TCPPacket;
import io.pkts.streams.Stream;
import io.pkts.streams.StreamListener;
import io.pkts.streams.StreamsTestBase;
import io.pkts.streams.TcpStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


/**
 *
 * End-to-end tests for the {@link  TcpStreamHandler} class.
 * The methodology here is to look if the handler identifies the same number
 * of streams as would wireshark for some captured traffic.
 *
 * @author sebastien.amelinclx@gmail.com
 */
public class TcpStreamHandlerTest {

    TcpStreamHandler streamHandler;

    @Before
    public void setUp(){
        streamHandler = new TcpStreamHandler();
        streamHandler.addStreamListener(new StreamListener<TCPPacket>() {
            @Override
            public void startStream(Stream<TCPPacket> stream, TCPPacket packet) {
                TcpStream tcpStream = (TcpStream) stream;
                //System.out.println("New stream n°"+tcpStream.getUuid()+ " has started");
            }

            @Override
            public void packetReceived(Stream<TCPPacket> stream, TCPPacket packet) {
                TcpStream tcpStream = (TcpStream) stream;
                //System.out.println("New packet for stream n°"+tcpStream.getUuid());
            }

            @Override
            public void endStream(Stream<TCPPacket> stream) {
                TcpStream tcpStream = (TcpStream) stream;
                //System.out.println("Stream n°"+tcpStream.getUuid()+ " has ended");
            }
        });
    }

    @After
    public void tearDown(){
    }

    /*
    *
    * General case tests with captured samples of traffic.
    *
     */
    @Test
    public void testBaseUsage() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/tcp_3_streams.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            Set<LongStreamId> keys = all_streams.keySet();
            assertEquals(3, keys.size());

            Collection<TcpStream> streams = all_streams.values();

            assertEquals(380, streams.stream().toList().get(0).getPackets().size());
            assertEquals(11, streams.stream().toList().get(1).getPackets().size());
            assertEquals(9, streams.stream().toList().get(2).getPackets().size());

        } catch (Exception e){
            e.printStackTrace();
            fail();
        }

    }

    /**
     * Test on captured web traffic containing 273 streams.
     */
    @Test
    public void testUserTraffic() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/user_traffic_1.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            Set<LongStreamId> keys = all_streams.keySet();
            assertEquals(273, keys.size());

        } catch (Exception e){
            e.printStackTrace();
        }

    }

    // single stream that after closing with an RST packet receives a FIN packet previously unseen
    @Test
    public void testFinNextBug() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/fin_bug.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(1, all_streams.size());

        } catch (Exception e){
            e.printStackTrace();
            fail();
        }
    }

    // single stream that exchanges keep-alives after closing.
    @Test
    public void testKeepAlive() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/ack_of_fin_and_rst_passed_closed.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(1, all_streams.size());

        } catch (Exception e){
            e.printStackTrace();
        }

    }

    // single stream that after closing receives an out-of-order packet.
    @Test
    public void testOutOfOrder() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/out_of_order.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(1, all_streams.size());

        } catch (Exception e){
            e.printStackTrace();
        }

    }

    /*
    *
    * Test on corner cases with synthetic traffic.
    *
     */

    /**
     * Test on a capture with two streams, each with a full handshake and 20 data packets,
     * with the second stream reusing the same ports as the first one.
     */
    @Test
    public void testReusingPorts(){
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/ports-reused-basic.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(2, all_streams.size());

            ArrayList<TcpStream> streams_tcp = new ArrayList<TcpStream>(all_streams.values());

            assertEquals(23, streams_tcp.get(0).getPackets().size());
            assertEquals(23, streams_tcp.get(1).getPackets().size());
        } catch (Exception e){
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Test on a capture with a duplicate syn packet. Should not split the stream because the second syn
     * is only a retransmission of the first one. Wireshark marks it as a 'reused port' packet but also as
     * a 'out-of-order' packet, but not as a 'retransmission' oddly enough. Despite this, it considers it part
     * of the same stream on it's first pass.
     * We expect the same behavior from the handler.
     */
    @Test
    public void testSynDuplicateAfterClosing(){
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/tcp_fin1_syn_dupli.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(1, all_streams.size());

        } catch (Exception e){
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Test on a capture with two streams, each with a full handshake and port reuse.
     * The second stream has a data packet that could be a retransmission of the first stream.
     * But, because it happens after a port reused, it is considered by wireshark as belonging
     * to the second stream on it's first pass and marked as a 'spurious retransmission' on the second pass.
     * We expect the same behavior from the handler.
     */
    @Test
    public void testSpuriousRetransmission(){
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/tcp_stream_spurious_retransmit.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(2, all_streams.size());

            ArrayList<TcpStream> streams_tcp = new ArrayList<TcpStream>(all_streams.values());

            assertEquals(9, streams_tcp.get(0).getPackets().size());
            assertEquals(4, streams_tcp.get(1).getPackets().size());
        } catch (Exception e){
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Test on a stream that closes with a RST packet and then receives 6 packets after 10 years of inactivity.
     * Despite the obvious timeout, wireshark still considers the packets as part of the same stream.
     * We expect the same behavior from the handler.
     */
    @Test
    public void testPacketBeyondTimeout(){
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/passed_timeout.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(1, all_streams.size());
        } catch (Exception e){
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Test on a stream that gets a packet with a lower sequence number than the base sequence number of
     * the stream. Despite this, wireshark still considers the packet as part of the same stream.
     * We expect the same behavior from the handler.
     */
    @Test
    public void testLowerSeq(){
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/passed_timeout.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            assertEquals(1, all_streams.size());
        } catch (Exception e){
            e.printStackTrace();
            fail();
        }
    }

}
