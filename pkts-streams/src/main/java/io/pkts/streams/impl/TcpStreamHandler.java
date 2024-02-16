package io.pkts.streams.impl;

import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.IPPacket;
import io.pkts.packet.PacketParseException;

import io.pkts.frame.Frame;
import io.pkts.framer.FramerManager;

import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

import io.pkts.streams.FragmentListener;
import io.pkts.streams.StreamHandler;
import io.pkts.streams.StreamListener;
import io.pkts.streams.SipStatistics;
import io.pkts.streams.Stream;
import io.pkts.streams.StreamId;
import io.pkts.streams.TcpStream;


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

    private class FiveTuple{
        public String sourceAddress;
        public String destinationAddress;
        public int sourcePort;
        public int destinationPort;
        public FiveTuple(String sourceAddress, String destinationAddress, int sourcePort, int destinationPort){
            this.sourceAddress = sourceAddress;
            this.destinationAddress = destinationAddress;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
        }
    }

    private final static Logger logger = LoggerFactory.getLogger(TcpStreamHandler.class);

    private final FramerManager framerManager;

    private StreamListener<TCPPacket> tcpListener;

    private FragmentListener fragmentListener;

    private final Map<StreamId, TcpStream> tcpStreams = new HashMap<StreamId, TcpStream>();

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
        return this.tcpStreams;
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

            if (packet.hasProtocol(Protocol.TCP)){
                this.processFrame(packet);
            }

        } catch (final IOException | PacketParseException e) {
            e.printStackTrace();
        }

        return true;
    }

    public void processFrame(final Packet frame) throws PacketParseException {
        //TODO:call streamListeners, define streams
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
}
