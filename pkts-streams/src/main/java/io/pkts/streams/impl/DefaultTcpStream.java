package io.pkts.streams.impl;

import io.hektor.fsm.FSM;
import io.hektor.fsm.TransitionListener;
import io.pkts.frame.PcapGlobalHeader;
import io.pkts.packet.TCPPacket;
import io.pkts.streams.StreamId;
import io.pkts.streams.TcpStream;
import io.pkts.streams.impl.tcpFSM.TcpStreamContext;
import io.pkts.streams.impl.tcpFSM.TcpStreamData;
import io.pkts.streams.impl.tcpFSM.TcpStreamFSM;
import io.pkts.streams.impl.tcpFSM.TcpStreamFSM.TcpState;


import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;

/**
 * @author sebastien.amelinckx@gmail.com
 */

public class DefaultTcpStream implements TcpStream {

    private final PcapGlobalHeader globalHeader;

    private final TransportStreamId id;
    private final long uuid;

    private final PriorityQueue<TCPPacket> packets; // Could not be a Set as packets with equal arrival time
                                                    // can be different packets.
    private final FSM fsm;


    public DefaultTcpStream(PcapGlobalHeader globalHeader, TransportStreamId id, long uuid, TransitionListener<TcpState> synListener){
        this.globalHeader = globalHeader;
        this.id = id;
        this.uuid = uuid;
        this.packets = new PriorityQueue<TCPPacket>(new PacketComparator());
        this.fsm = TcpStreamFSM.definition.newInstance(uuid, new TcpStreamContext(), new TcpStreamData(), null, synListener);
        fsm.start();
    }
    @Override
    public List<TCPPacket> getPackets() {
        return new ArrayList<TCPPacket>(this.packets);
    }

    @Override
    public long getDuration() {
        return this.getTimeOfLastPacket() - this.getTimeOfFirstPacket();
    }

    @Override
    public long getTimeOfFirstPacket() {
        if (this.packets.isEmpty()) {
            return -1;
        }

        return packets.peek().getArrivalTime();
    }

    @Override
    public long getTimeOfLastPacket() {
        if (this.packets.isEmpty()) {
            return -1;
        }

        TCPPacket last = null;
        for (TCPPacket packet : packets){
            last = packet;
        }

        return last.getArrivalTime();
    }

    @Override
    public StreamId getStreamIdentifier() {
        return this.id;
    }

    @Override
    public void write(OutputStream out) throws IOException {
        throw new UnsupportedOperationException("Writing out a DefaultTCPStream is Unsupported");
    }

    @Override
    public String getSrcAddr() {
        return id.getSourceAddress();
    }

    @Override
    public String getDestAddr() {
        return id.getDestinationAddress();
    }

    @Override
    public int getSrcPort() {
        return id.getSourcePort();
    }

    @Override
    public int getDestPort() {
        return id.getDestinationPort();
    }

    @Override
    public void addPacket(TCPPacket packet){
        fsm.onEvent(packet);
        // if new syn exchange, a new stream will be started by the synListener
        // in that case, no need to add the new syn packet to the stream
        if (fsm.getState() != TcpState.CLOSED_PORTS_REUSED){
            packets.add(packet);
        }
    }

    @Override
    public TcpState getState(){
        return (TcpState) fsm.getState();
    }

    @Override
    public long getUuid(){
        return this.uuid;
    }

    /**
     * A TCP stream is ended when the connection ends, but even in this state
     * a stream can receive new arriving packets. So, the stream is ended in the
     * closed state, but also when the ports are reused which is the terminal state
     * of the {@link TcpStreamFSM}.
     */
    @Override
    public boolean Ended() {
        return fsm.getState() == TcpState.CLOSED || fsm.getState() == TcpState.CLOSED_PORTS_REUSED;
    }

}
