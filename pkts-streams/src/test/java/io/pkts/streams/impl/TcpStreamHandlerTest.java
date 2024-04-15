package io.pkts.streams.impl;


import io.pkts.Pcap;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.streams.Stream;
import io.pkts.streams.StreamListener;
import io.pkts.streams.StreamsTestBase;
import io.pkts.streams.TcpStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.*;


public class TcpStreamHandlerTest {

    TcpStreamHandler streamHandler;

    @Before
    public void setUp() throws Exception {
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
    public void tearDown() throws Exception {
    }

    @Test
    public void testBaseUsage() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/tcp_3_streams.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            Set<LongStreamId> keys = all_streams.keySet();

            for (LongStreamId uuid : keys){
                System.out.println("found uuid " + uuid.asString());
            }

            ArrayList<TcpStream> streams = new ArrayList<TcpStream>(all_streams.values());

            List<TCPPacket> second = streams.get(2).getPackets();

            System.out.println("Stream id is " + streams.get(1).getStreamIdentifier());

            System.out.println("-----------");
            System.out.println("Packets are:");
            for (TCPPacket packet : second){
                System.out.println("ip src: " + packet.getParentPacket().getSourceIP());
                System.out.println("ip dest: " + packet.getParentPacket().getDestinationIP());
                System.out.println("source port: " + packet.getSourcePort());
                System.out.println("destination port: " + packet.getDestinationPort());
                System.out.println("seq_num: " + packet.getSequenceNumber());

                if (packet.isSYN()){
                    System.out.println("Packet has SYN flag");
                }
                if (packet.isFIN()){
                    System.out.println("Packet has FIN flag");
                }
                if (packet.isRST()){
                    System.out.println("Packet has RST flag");
                }
                if (packet.isACK()) {
                    System.out.println("Packet has ACK flag, ack="+packet.getAcknowledgementNumber());
                }


                System.out.println("packet payload: ");

                System.out.println(packet.getPayload());

                System.out.println();
            }


        } catch (Exception e){
            e.printStackTrace();
        }

    }

    @Test
    public void testUserTraffic1() {
        try {
            Pcap pcap = Pcap.openStream(StreamsTestBase.class.getResourceAsStream("tcp-streams/user_traffic_1.pcap"));
            pcap.loop(streamHandler);

            Map all_streams = streamHandler.getStreams();

            Set<LongStreamId> keys = all_streams.keySet();

            for (LongStreamId uuid : keys){
                System.out.println("found uuid " + uuid.asString());
            }

        } catch (Exception e){
            e.printStackTrace();
        }

    }
}
