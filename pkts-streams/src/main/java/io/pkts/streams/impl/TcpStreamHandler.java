package io.pkts.streams.impl;

import io.hektor.fsm.TransitionListener;
import io.pkts.frame.PcapGlobalHeader;
import io.pkts.packet.*;

import io.pkts.frame.Frame;
import io.pkts.framer.FramerManager;

import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.Map;

import io.pkts.streams.FragmentListener;
import io.pkts.streams.StreamHandler;
import io.pkts.streams.StreamListener;
import io.pkts.streams.SipStatistics;
import io.pkts.streams.Stream;
import io.pkts.streams.StreamId;
import io.pkts.streams.TcpStream;


import io.pkts.streams.impl.tcpFSM.TcpStreamFSM.TcpState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link StreamHandler} for TCP conversations.
 * The handler will figure out if the received {@link Frame} contains a TCP packet and if so,
 * will parse the {@link Frame} in a {@link TCPPacket} and add it to the corresponding Stream.
 * A stream of TCP packets is identified by a 5-tuple (src addr, dest addr, src port, dest port, TCP protocol),
 * with the additional catch that a stream CAN be ended either by a TCP packet with the RST flag, or by a FIN 4-way
 * handshake (or a 3-way handshake with FIN+ACK). A stream of TCP packets CAN be started with a SYN 3-way handshake,
 * but in case a new 5-tuple is observed with no 3-way handshake it will be assumed that a new stream has started.
 * IP fragmentation is not handled by this class, but adding a {@link FragmentListener} is supported.
 *
 * @author sebastien.amelinckx@gmail.com
 */
public class TcpStreamHandler implements StreamHandler {

    /**
    * Class implementing a {@link TransitionListener} to check if a stream closes due to a new SYN packet
    *  in which case a new stream has to be started from that same closing SYN packet.
    * */
    private class SynListener implements TransitionListener<TcpState>{
        @Override
        public void onTransition(TcpState currentState, TcpState toState, Object o) {
            if (!(o instanceof TCPPacket)){
                throw new RuntimeException("Object passed to TcpFSM is of Class: " + o.getClass());
            } else if (toState == TcpState.CLOSED && ((TCPPacket) o).isSYN()) {
                startNewStream((TCPPacket) o);
            }
        }
    }


    private final static Logger logger = LoggerFactory.getLogger(TcpStreamHandler.class);

    private final FramerManager framerManager;

    private StreamListener<TCPPacket> tcpListener;

    private FragmentListener fragmentListener;

    // This map is for looking up what streams are open and attribute packets to them
    private final Map<StreamId, TcpStream> openTcpStreams = new HashMap<StreamId, TcpStream>();
    
    // This map is for the user to recover all streams
    private final Map<StreamId, TcpStream> streams = new LinkedHashMap<StreamId, TcpStream>();
    private int uuid_counter = 0;

    public TcpStreamHandler() {
        this.framerManager = FramerManager.getInstance();
    }


    @Override
    public void addStreamListener(StreamListener<? extends Packet> listener) throws IllegalArgumentException {
        try {
            final Method method = listener.getClass().getMethod("endStream", Stream.class);
            final ParameterizedType parameterizedType = (ParameterizedType) method.getGenericParameterTypes()[0];
            final Type[] parameterArgTypes = parameterizedType.getActualTypeArguments();

            final Type parameterArgType = parameterArgTypes[0];
            final Class<?> parameterArgClass = (Class<?>) parameterArgType;
            if (parameterArgClass.equals(TCPPacket.class)) {
                this.tcpListener = (StreamListener<TCPPacket>) listener;
            } else {
                throw new ClassCastException();
            }

        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new RuntimeException("Unable to figure out the paramterized type", e);
        } catch (final SecurityException e) {
            throw new RuntimeException("Unable to access method information due to security constraints", e);
        } catch (final NoSuchMethodException e) {
            throw new RuntimeException("The startStream method doesn't exist. Signature changed?", e);
        } catch (final ClassCastException e) {
            // means that the user had not parameterized the StreamListener
            // interface, which means that we cannot actually detect streams.
            throw new IllegalArgumentException("The supplied listener has not been correctly parameterized");
        }
    }

    @Override
    public void setFragmentListener(FragmentListener fragmentListener) {
        this.fragmentListener = fragmentListener;
    }

    @Override
    public SipStatistics getSipStatistics() {
        throw new UnsupportedOperationException("Getting Sip Statistics from a TCPStreamHandler is Unsupported");
    }

    @Override
    public Map<StreamId, ? extends Stream> getStreams() {
        return this.streams;
    }

    @Override
    public boolean nextPacket(Packet packet) throws IOException {
        try {
            if (packet.hasProtocol(Protocol.IPv4)) { // handle IPv4 fragmentation notification
                final IPPacket ip = (IPPacket) packet.getPacket(Protocol.IPv4);
                if (ip.isFragmented()) {
                    packet = handleFragmentation(ip);
                    if (packet == null) {
                        return true;
                    }
                }
            } else if (packet.hasProtocol(Protocol.IPv6)){ // handle IPv6 fragmentation notification
                final IPPacket ip = (IPPacket) packet.getPacket(Protocol.IPv6);
                if (ip.isFragmented()) {
                    packet = handleFragmentation(ip);
                    if (packet == null) {
                        return true;
                    }
                }
            }

            if (packet.hasProtocol(Protocol.TCP) &&
                    (packet.hasProtocol(Protocol.IPv4) || packet.hasProtocol(Protocol.IPv6))) {
                this.processFrame(packet);
            }

        } catch (final IOException | PacketParseException e) {
            e.printStackTrace();
        }

        return true;
    }

    public void processFrame(final Packet frame) throws PacketParseException {
        try {
            final IPPacket ipPacket =
                    frame.hasProtocol(Protocol.IPv4) ?
                            (IPv4Packet) frame.getPacket(Protocol.IPv4)
                            : (frame.hasProtocol(Protocol.IPv6) ? (IPv6Packet) frame.getPacket(Protocol.IPv6) : null);

            final TCPPacket tcpPacket = (TCPPacket) frame.getPacket(Protocol.TCP);

            if (ipPacket == null || tcpPacket == null){
                throw new NullPointerException("tcp or ip packet was null when processed");
            }

            final TransportStreamId pktStreamId = new TransportStreamId(tcpPacket);

            TcpStream stream = openTcpStreams.get(pktStreamId);
            stream = (stream == null) ? openTcpStreams.get(pktStreamId.oppositeFlowDirection()) : stream;

            if (stream == null) {
                // TODO should use contains to look for an equal 5-tuple before cheking if the packets belongs.
                for (TcpStream tcpStream : streams.values()){ // lookup closed streams to see if packet belongs there.
                    if(belongsToClosedStream(tcpPacket, (DefaultTcpStream) tcpStream)){
                        tcpStream.addPacket(tcpPacket);
                        this.notifyPacketReceived(tcpStream, tcpPacket); // a closed stream received a packet !
                        //System.out.println("Closed stream received a packet !!!!");
                        return; // packet added to old stream, do not start a new one, processing of packet ended.
                    }
                }

                startNewStream(tcpPacket);
            } else {
                stream.addPacket(tcpPacket);
                this.notifyPacketReceived(stream, tcpPacket);
                TcpState streamState = stream.getState();
                if (streamState == TcpState.CLOSED){
                    endStream(stream);
                }
            }

        } catch (Exception e){
            e.printStackTrace();
        }
    }


    private IPPacket handleFragmentation(final IPPacket ipPacket) {
        if (this.fragmentListener == null) {
            return null;
        }
        try {
            return this.fragmentListener.handleFragment(ipPacket);
        } catch (final Throwable t) {
            logger.warn("Exception thrown by FragmentListener when processing the IP frame", t);
        }
        return null;
    }

    private void notifyStartStream(final TcpStream stream, final TCPPacket pkt) {
        if (this.tcpListener != null) {
            this.tcpListener.startStream(stream, pkt);
        }
    }

    private void notifyPacketReceived(final TcpStream stream, final TCPPacket pkt) {
        if (this.tcpListener != null) {
            this.tcpListener.packetReceived(stream, pkt);
        }
    }

    private void notifyEndStream(final TcpStream stream) {
        if (this.tcpListener != null) {
            this.tcpListener.endStream(stream);
        }
    }

    private PcapGlobalHeader assignGlobalHeader(Packet frame) throws PacketParseException{
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

    private void startNewStream(TCPPacket packet){
        TransportStreamId pktStreamId = new TransportStreamId(packet);

        PcapGlobalHeader header = assignGlobalHeader(packet.getParentPacket().getParentPacket());
        TcpStream stream = new DefaultTcpStream(header, pktStreamId, uuid_counter++, new SynListener());

        this.openTcpStreams.put(pktStreamId, stream);
        this.streams.put(new LongStreamId(stream.getUuid()), stream);
        stream.addPacket(packet);
        this.notifyStartStream(stream, packet);
    }

    private void endStream(TcpStream stream){
        openTcpStreams.remove(stream.getStreamIdentifier(), stream);
        this.notifyEndStream(stream);
    }

    /**
     * Handling of duplicate RST or FIN packets, or next in sequence packets, on an already closed stream.
     * This situation may come if one of the clients closes the connection by sending it's signaling flags,
     * but those packets don't reach the other client, making that client send other data and making
     * the closing client resend those signalling packets. Those duplicates and next in sequence packets
     * belong the corresponding closed conversation. Because of this when a new stream is created we have
     * to check that the new packet does not have it's place among all ended streams.
     *
     * @author sebastien.amelinckx@gmail.com
     */
    private boolean belongsToClosedStream(TCPPacket packet, DefaultTcpStream stream){
        // TODO what if multiple closed streams have the same 5-tuple ??
        TransportStreamId streamId = (TransportStreamId) stream.getStreamIdentifier();
        TcpDuplicateHandler duplicateHandler = stream.getDuplicateHandler();

        if (!(streamId.equals(new TransportStreamId(packet)) || streamId.oppositeFlowDirection().equals(new TransportStreamId(packet)))){ // has to match closed stream's 5-tuple
            return false;
        }

        return duplicateHandler.matchDuplicate(packet);
    }
}
