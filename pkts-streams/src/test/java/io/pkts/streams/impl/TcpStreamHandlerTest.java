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

    //TODO

}
