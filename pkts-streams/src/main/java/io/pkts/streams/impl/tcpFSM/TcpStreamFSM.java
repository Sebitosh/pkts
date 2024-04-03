package io.pkts.streams.impl.tcpFSM;

import io.hektor.fsm.Definition;
import io.hektor.fsm.FSM;
import io.hektor.fsm.builder.FSMBuilder;
import io.hektor.fsm.builder.StateBuilder;
import io.pkts.packet.TCPPacket;
import io.pkts.streams.impl.TransportStreamId;

import static io.pkts.streams.impl.tcpFSM.TcpStreamFSM.TcpState.*;

public class TcpStreamFSM{
    public final static Definition<TcpState, TcpStreamContext, TcpStreamData> definition;
    public enum TcpState{
        INIT, HANDSHAKE, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
        CLOSING_1_CLOSING_2, CLOSED_1_CLOSING_2, CLOSING_1_CLOSED_2, CLOSED
    }

    static {
        final FSMBuilder<TcpState, TcpStreamContext, TcpStreamData> builder=
                FSM.of(TcpState.class).ofContextType(TcpStreamContext.class).withDataType(TcpStreamData.class);

        builder.withFriendlyName("TCP_stream");

        // define all states for the builder
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> init = builder.withInitialState(INIT);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> handshake = builder.withState(HANDSHAKE);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> established = builder.withState(ESTABLISHED);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> finWait1 = builder.withState(FIN_WAIT_1);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> finWait2 = builder.withState(FIN_WAIT_2);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> closing1Closing2 = builder.withState(CLOSING_1_CLOSING_2);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> closed1Closing2 = builder.withState(CLOSED_1_CLOSING_2);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> closing1Closed2 = builder.withState(CLOSING_1_CLOSED_2);
        final StateBuilder<TcpState, TcpStreamContext, TcpStreamData> closed = builder.withFinalState(CLOSED);

        // define all transitions
        init.transitionTo(HANDSHAKE).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        init.transitionTo(FIN_WAIT_1).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isFinPacket);
        init.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        init.transitionTo(ESTABLISHED).onEvent(TCPPacket.class);

        handshake.transitionToSelf().onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        handshake.transitionTo(FIN_WAIT_1).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isFinPacket).withAction(TcpStreamFSM::setFin1);
        handshake.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        handshake.transitionTo(ESTABLISHED).onEvent(TCPPacket.class);

        established.transitionTo(FIN_WAIT_1).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isFinPacket).withAction(TcpStreamFSM::setFin1);
        established.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        established.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket); // skipped the end of stream, New stream noticed
        established.transitionToSelf().onEvent(TCPPacket.class);

        finWait1.transitionTo(CLOSED_1_CLOSING_2).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::ackOfFin1AndFin2).withAction(TcpStreamFSM::closeFin1SetFin2); // special case FIN + ACKofFin1 packet
        finWait1.transitionTo(FIN_WAIT_2).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isAckOfFin1).withAction(TcpStreamFSM::closeFin1); // if first fin has been acked
        finWait1.transitionTo(CLOSING_1_CLOSING_2).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSecondFinPacket).withAction(TcpStreamFSM::setFin2);
        finWait1.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        finWait1.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        finWait1.transitionToSelf().onEvent(TCPPacket.class);

        finWait2.transitionTo(CLOSED_1_CLOSING_2).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSecondFinPacket).withAction(TcpStreamFSM::setFin2); // 2nd fin observed
        finWait2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        finWait2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        finWait2.transitionToSelf().onEvent(TCPPacket.class);

        closing1Closing2.transitionTo(CLOSED_1_CLOSING_2).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isAckOfFin1).withAction(TcpStreamFSM::closeFin1);
        closing1Closing2.transitionTo(CLOSING_1_CLOSED_2).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isAckOfFin2).withAction(TcpStreamFSM::closeFin2);
        closing1Closing2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        closing1Closing2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        closing1Closing2.transitionToSelf().onEvent(TCPPacket.class);

        closed1Closing2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isAckOfFin2).withAction(TcpStreamFSM::closeFin2);
        closed1Closing2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        closed1Closing2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        closed1Closing2.transitionToSelf().onEvent(TCPPacket.class);

        closing1Closed2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isAckOfFin1).withAction(TcpStreamFSM::closeFin1);
        closing1Closed2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isRstPacket);
        closing1Closed2.transitionTo(CLOSED).onEvent(TCPPacket.class).withGuard(TcpStreamFSM::isSynPacket);
        closing1Closed2.transitionToSelf().onEvent(TCPPacket.class);


        definition = builder.build();
    }

    private static boolean isSynPacket(TCPPacket packet){
        return packet.isSYN();
    }

    private static boolean isFinPacket(TCPPacket packet){
        return packet.isFIN();
    }

    private static boolean isSecondFinPacket(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){ // check if FIN segment comes from the second party
        return packet.isFIN() && (!data.getFIN_1_id().equals(new TransportStreamId(packet))); // is it a FIN segment AND not coming from the same direction as FIN_1
    }

    private static boolean isRstPacket(TCPPacket packet){
        return packet.isRST();
    }

    private static void setFin1(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        data.setFIN_1_seq(packet);
    }

    private static void setFin2(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        data.setFIN_2_seq(packet);
    }

    private static void closeFin1(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        data.terminateFIN_1();
    }

    private static void closeFin2(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        data.terminateFIN_2();
    }

    private static boolean isAckOfFin1(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        if (!packet.isACK()){ // check Ack flag is set
            return false;
        }
        else if (data.isFIN_1_Terminated()){ // if side 1 is already closed
            return false;
        }
        else if(!data.getFIN_1_id().equals((new TransportStreamId(packet).oppositeFlowDirection()))){ // ack has to come from opposite party
            return false;
        }
        else return data.getFIN_1_seq() < packet.getAcknowledgementNumber();
    }

    private static boolean isAckOfFin2(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        if (!packet.isACK()){ // check Ack flag is set
            return false;
        }
        else if (data.isFIN_2_Terminated()){ // if side 2 is already closed
            return false;
        }
        else if(!data.getFIN_2_id().equals((new TransportStreamId(packet).oppositeFlowDirection()))){ // ack has to come from opposite party
            return false;
        }
        else return data.getFIN_2_seq() < packet.getAcknowledgementNumber();
    }

    private static boolean ackOfFin1AndFin2(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        return isAckOfFin1(packet, ctx, data) && isSecondFinPacket(packet, ctx, data);
    }

    private static void closeFin1SetFin2(TCPPacket packet, TcpStreamContext ctx, TcpStreamData data){
        closeFin1(packet, ctx, data);
        setFin2(packet, ctx, data);
    }
}
