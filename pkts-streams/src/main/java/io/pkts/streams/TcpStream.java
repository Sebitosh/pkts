package io.pkts.streams;

import io.pkts.packet.TCPPacket;
import io.pkts.streams.impl.tcpFSM.TcpStreamFSM.TcpState;

public interface TcpStream extends Stream {
    // What do I want here ?
    // Probably layer 3 information
    // Maybe some statistics
    // Maybe some indication of state

    public String getSrcAddr();

    public String getDestAddr();

    public int getSrcPort();

    public int getDestPort();

    void addPacket(TCPPacket packet);

    TcpState getState();

    long getUuid();

    public boolean ended();
}
