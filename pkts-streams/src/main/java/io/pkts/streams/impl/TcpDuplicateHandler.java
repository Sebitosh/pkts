package io.pkts.streams.impl;

import io.pkts.packet.TCPPacket;

public class TcpDuplicateHandler {
    private static final long maxSeqNum = (1L << 32) - 1; // seq nums are encoded in 32 bits, used to modulo next expected seq num
    private long seqRst1 = -1;
    private long seqRst2 = -1; // for the rare case of two way RST
    private long seqFin1 = -1;
    private long seqFin2 = -1;
    private long nextSeq1 = -1;
    private long nextSeq2 = -1;

    private TransportStreamId rst1Id;
    private TransportStreamId rst2Id;
    private TransportStreamId fin1Id;
    private TransportStreamId fin2Id;
    private TransportStreamId next1Id;
    private TransportStreamId next2Id;


    public TcpDuplicateHandler(){}
    private void setNextSeq1(long lastPacketLength) {
        if (lastPacketLength == 0){ // if len null, then next seq is simply incremented by 1
            this.nextSeq1 = (nextSeq1 + 1) % maxSeqNum;
        } else {
            this.nextSeq1 = (nextSeq1 + lastPacketLength) % maxSeqNum;
        }
    }

    private void setNextSeq2(long lastPacketLength) {
        if (lastPacketLength == 0){ // if len null, then next seq is simply incremented by 1
            this.nextSeq2 = (nextSeq2 + 1) % maxSeqNum;;
        } else {
            this.nextSeq2 = (nextSeq2 + lastPacketLength) % maxSeqNum;
        }
    }

    private boolean matchRst1(TCPPacket packet){
        return packet.getSequenceNumber() == seqRst1 && rst1Id.equals(new TransportStreamId(packet));
    }

    private boolean matchRst2(TCPPacket packet){
        return packet.getSequenceNumber() == seqRst2 && rst2Id.equals(new TransportStreamId(packet));
    }

    private boolean matchFin1(TCPPacket packet){
        return packet.getSequenceNumber() == seqFin1 && fin1Id.equals(new TransportStreamId(packet));
    }

    private boolean matchFin2(TCPPacket packet){
        return packet.getSequenceNumber() == seqFin2 && fin2Id.equals(new TransportStreamId(packet));
    }

    private boolean matchAckOfFin1(TCPPacket packet){
        return packet.getAcknowledgementNumber() == seqFin1 && fin1Id.oppositeFlowDirection().equals(new TransportStreamId(packet));
    }

    private boolean matchAckOfFin2(TCPPacket packet){
        return packet.getAcknowledgementNumber() == seqFin2 && fin2Id.oppositeFlowDirection().equals(new TransportStreamId(packet));
    }

    private boolean matchNext1(TCPPacket packet){
        return packet.getSequenceNumber() == nextSeq1 && next1Id.equals(new TransportStreamId(packet));
    }

    private boolean matchNext2(TCPPacket packet){
        return packet.getSequenceNumber() == nextSeq2 && next2Id.equals(new TransportStreamId(packet));
    }

    public boolean matchDuplicate(TCPPacket packet){
        return matchRst1(packet) || matchRst2(packet) || // case of duplicate RST
               matchFin1(packet) || matchFin2(packet) || // case of duplicate FIN
               matchAckOfFin1(packet) || matchAckOfFin2(packet) || // case of ack of duplicate FIN
               matchNext1(packet) || matchNext2(packet); // case of next in sequence packet
    }
    
    public void setupDuplicateHandler(TCPPacket packet){
        TransportStreamId packetStreamId = new TransportStreamId(packet);

        if (packet.isRST()){
            if (seqRst1 == -1){ // RST 1 not set yet
                seqRst1 = packet.getSequenceNumber();
                rst1Id = packetStreamId;
            } else if (seqRst2 == -1 && rst1Id.equals(packetStreamId.oppositeFlowDirection())){ // RST 2 not set yet and rst coming from opposite direction
                seqRst2 = packet.getSequenceNumber();
                rst2Id = packetStreamId;
            }
            // their should not be a reset of RST sequence values once they are both set, or if two different values are coming from the same direction
        }
        
        if (packet.isFIN()) {
            if (seqFin1 == -1){ // FIN 1 not set yet
                seqFin1 = packet.getSequenceNumber();
                fin1Id = packetStreamId;
            } else if (seqFin2 == -1 && fin1Id.equals(packetStreamId.oppositeFlowDirection())) { // FIN 2 not set yet and fin coming from opposite direction
                seqFin2 = packet.getSequenceNumber();
                fin2Id = packetStreamId;
            }
            // their should not be a reset of FIN sequence values once they are both set, or if two different values are coming from the same direction
        }
        
        if (next1Id == null){
            next1Id = packetStreamId;
        } else if (next2Id == null  && next1Id.equals(packetStreamId.oppositeFlowDirection())) {
            next2Id = packetStreamId;
        }
                                                                                        // but what if missed segment occurs when seq nums loop back to 0 ? does <= cause a bug then ?
        if (packetStreamId.equals(next1Id) && nextSeq1 <= packet.getSequenceNumber()){ // if from direction 1 and sequence number equal or higher (if missed segment) than expected next segment seq num
            setNextSeq1(packet.getSequenceNumber());
        } else if (packetStreamId.equals(next2Id) && nextSeq2 <= packet.getSequenceNumber()) { // same for direction 2
            setNextSeq2(packet.getSequenceNumber());
        }
    }
}
