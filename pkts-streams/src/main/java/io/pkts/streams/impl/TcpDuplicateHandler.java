package io.pkts.streams.impl;

import io.pkts.buffer.Buffer;
import io.pkts.packet.TCPPacket;

import java.util.ArrayList;

/**
 *
 * This class handles the logic for detecting duplicate packets in a seemingly Closed TCP stream.
 * Multiple cases can occur where a packet belongs to a closed stream:
 * 1. If the received packet corresponds to a duplicate of one of the signaling packets closing the connection (RST, FIN, or ACK of FIN)
 * 2. If the received packet corresponds to a packet that is out of order but still within the expected sequence numbers
 * 3. If the received packet corresponds to a packet that is in sequence with the last packet of the stream. This
 * can happen due to keep-alive or data packets that are sent after the connection is closed, triggering TCP clients to
 * send other RST packets in the stream.
 *
 */
public class TcpDuplicateHandler {
    private static final long MAX_SEQ_NUM = (1L << 32); // seq nums are encoded in 32 bits, used to modulo next expected seq num

    private long baseSeq1 = -1;
    private long baseSeq2 = -1;
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
    private TransportStreamId flow1Id;
    private TransportStreamId flow2Id;

    //private ArrayList debugSeqNums = new ArrayList<>();
    //private ArrayList debugNextSeqNums = new ArrayList<>();


    public TcpDuplicateHandler(){}
    private void setNextSeq1(TCPPacket packet) {
        if (nextSeq1 == -1){ // first packet in this direction
            nextSeq1 = packet.getSequenceNumber(); // set base sequence number
        }

        int lastPacketLength = packetPayloadLength(packet);

        if (lastPacketLength == 0){ // if len null, then next seq is simply incremented by 1
            if (packet.isACK() && !packet.isSYN() && !packet.isFIN()){ //unless it is an ACK only packet ?? CAREFULL ACK ONLY, NO FIN + ACK
                return;
            }
            this.nextSeq1 = (packet.getSequenceNumber() + 1) % MAX_SEQ_NUM;
        } else {
            this.nextSeq1 = (packet.getSequenceNumber() + lastPacketLength) % MAX_SEQ_NUM;
        }
    }

    private void setNextSeq2(TCPPacket packet) {
        //long seqNum = packet.getSequenceNumber();
        //debugSeqNums.add(seqNum);
        if (nextSeq2 == -1){ // first packet in this direction
            nextSeq2 = packet.getSequenceNumber(); // set base sequence number
        }

        int lastPacketLength = packetPayloadLength(packet);


        if (lastPacketLength == 0){ // if len null, then next seq is simply incremented by 1
            if (packet.isACK() && !packet.isSYN() && !packet.isFIN()){ //unless it is an ACK only packet ??
                return;
            }
            this.nextSeq2 = (packet.getSequenceNumber() + 1) % MAX_SEQ_NUM;;
        } else {
            this.nextSeq2 = (packet.getSequenceNumber() + lastPacketLength) % MAX_SEQ_NUM;
        }

        //debugNextSeqNums.add(nextSeq2);

    }

    private boolean matchRst1(TCPPacket packet){
        return packet.isRST() && packet.getSequenceNumber() == seqRst1 && rst1Id.equals(new TransportStreamId(packet));
    }

    private boolean matchRst2(TCPPacket packet){
        return packet.isRST() && packet.getSequenceNumber() == seqRst2 && rst2Id.equals(new TransportStreamId(packet));
    }

    private boolean matchFin1(TCPPacket packet){
        return packet.isFIN() && packet.getSequenceNumber() == seqFin1 && fin1Id.equals(new TransportStreamId(packet));
    }

    private boolean matchFin2(TCPPacket packet){
        return packet.isFIN() && packet.getSequenceNumber() == seqFin2 && fin2Id.equals(new TransportStreamId(packet));
    }

    private boolean matchAckOfFin1(TCPPacket packet){
        return packet.isACK() && packet.getAcknowledgementNumber() == seqFin1 && fin1Id.oppositeFlowDirection().equals(new TransportStreamId(packet))
               && relativeLessThanOrEqual(packet.getSequenceNumber(), nextSeq2, baseSeq2);
    }

    private boolean matchAckOfFin2(TCPPacket packet){
        return packet.isACK() && packet.getAcknowledgementNumber() == seqFin2 && fin2Id.oppositeFlowDirection().equals(new TransportStreamId(packet))
               && relativeLessThanOrEqual(packet.getSequenceNumber(), nextSeq1, baseSeq1);
    }

    private boolean matchNext1(TCPPacket packet){
        return relativeLessThanOrEqual(packet.getSequenceNumber(), nextSeq1, baseSeq1)// <= because packet could be out of order
                && flow1Id.equals(new TransportStreamId(packet)); // trust TCP clients to not send RST or FIN after connection is closed
    }

    private boolean matchNext2(TCPPacket packet){
        return relativeLessThanOrEqual(packet.getSequenceNumber(), nextSeq2, baseSeq2)
                && flow2Id.equals(new TransportStreamId(packet)); // <= because packet could be out of order
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
        
        if (flow1Id == null){
            flow1Id = packetStreamId;
            baseSeq1 = packet.getSequenceNumber(); // set first sequence number
        } else if (flow2Id == null  && flow1Id.equals(packetStreamId.oppositeFlowDirection())) {
            flow2Id = packetStreamId;
            baseSeq2 = packet.getSequenceNumber(); // set first sequence number in second direction
        }
                                                                                        // but what if missed segment occurs when seq nums loop back to 0 ? does <= cause a bug then ?
        if (packetStreamId.equals(flow1Id) && nextSeq1 <= packet.getSequenceNumber()){ // if from direction 1 and sequence number equal or higher (if missed segment) than expected next segment seq num
            setNextSeq1(packet);
        } else if (packetStreamId.equals(flow2Id) && nextSeq2 <= packet.getSequenceNumber()) { // same for direction 2
            setNextSeq2(packet);
        }
    }

    // should this be a TCPPacket method ?
    private static int packetPayloadLength(TCPPacket packet){
        Buffer buff = packet.getPayload();
        if (buff == null){
            return 0;
        } else{
            return buff.capacity();
        }
    }

    // Method to normalize the sequence numbers
    private static long normalizeSeqNum(long seqNum, long baseSeqNum) {
        return (seqNum - baseSeqNum + MAX_SEQ_NUM) % MAX_SEQ_NUM;
    }

    // Method to compare two relative sequence numbers to consider wraparound of sequence numbers
    private static boolean relativeLessThanOrEqual(long seqNum1, long seqNum2, long baseSeqNum) {
        long normalizedSeqNum1 = normalizeSeqNum(seqNum1, baseSeqNum);
        long normalizedSeqNum2 = normalizeSeqNum(seqNum2, baseSeqNum);
        return normalizedSeqNum1 <= normalizedSeqNum2;
    }
}
