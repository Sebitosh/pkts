package io.pkts.streams.impl;

import io.pkts.frame.PcapGlobalHeader;
import io.pkts.packet.TCPPacket;
import io.pkts.streams.StreamId;
import io.pkts.streams.TcpStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.NavigableSet;
import java.util.TreeSet;

public class DefaultTcpStream implements TcpStream {



    private final PcapGlobalHeader globalHeader;

    private final LongStreamId id;

    private final NavigableSet<TCPPacket> packets;

    public DefaultTcpStream(PcapGlobalHeader globalHeader, LongStreamId id){
        this.globalHeader = globalHeader;
        this.id = id;
        this.packets = new TreeSet<TCPPacket>();
    }
    @Override
    public List getPackets() {
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

        return packets.first().getArrivalTime();
    }

    @Override
    public long getTimeOfLastPacket() {
        if (this.packets.isEmpty()) {
            return -1;
        }

        return packets.last().getArrivalTime();
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
        //TODO
        return null;
    }

    @Override
    public String getDestAddr() {
        //TODO
        return null;
    }

    @Override
    public int getSrcPort() {
        //TODO
        return 0;
    }

    @Override
    public int getDestPort() {
        //TODO
        return 0;
    }

    @Override
    public boolean ended() {
        //TODO
        return false;
    }

    @Override
    public boolean endedGracefully() {
        //TODO
        return false;
    }

    @Override
    public boolean endedAbruptly() {
        //TODO
        return false;
    }
}
