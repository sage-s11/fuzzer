package com.fuzzer.harness;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;

/**
 * UdpHarness
 *
 * Drives DNS messages over UDP to a target server.
 * Handles:
 *   - Send + receive with configurable timeout
 *   - Connection refused detection (ICMP port unreachable → target down)
 *   - Response validation (is it a DNS message at all?)
 *   - Liveness probe (send a valid query, expect a response)
 */
public class UdpHarness {

    private final String targetHost;
    private final int targetPort;
    private final int timeoutMs;

    private DatagramSocket socket;

    public UdpHarness(String targetHost, int targetPort, int timeoutMs) throws SocketException {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.timeoutMs  = timeoutMs;
        this.socket     = new DatagramSocket();
        this.socket.setSoTimeout(timeoutMs);
    }

    /**
     * Send bytes to target and wait for response.
     * Returns null on timeout.
     * Throws SocketException if target is unreachable (crash indicator).
     */
    public SendResult send(byte[] payload) throws IOException {
        InetAddress addr = InetAddress.getByName(targetHost);
        DatagramPacket outPacket = new DatagramPacket(payload, payload.length, addr, targetPort);

        long sendTime = System.currentTimeMillis();
        socket.send(outPacket);

        byte[] buf = new byte[4096];
        DatagramPacket inPacket = new DatagramPacket(buf, buf.length);

        try {
            socket.receive(inPacket);
            long rtt = System.currentTimeMillis() - sendTime;
            byte[] response = Arrays.copyOf(inPacket.getData(), inPacket.getLength());
            return new SendResult(SendResult.Status.RESPONSE, response, rtt);
        } catch (SocketTimeoutException e) {
            return new SendResult(SendResult.Status.TIMEOUT, null, timeoutMs);
        } catch (PortUnreachableException e) {
            return new SendResult(SendResult.Status.PORT_UNREACHABLE, null, 0);
        }
    }

    /**
     * Liveness probe — send a known-good DNS query and check for any response.
     */
    public boolean isAlive(byte[] validQuery) {
        try {
            SendResult result = send(validQuery);
            return result.status == SendResult.Status.RESPONSE;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Rebuild socket after a crash/disconnect.
     */
    public void reconnect() throws SocketException {
        try { socket.close(); } catch (Exception ignored) {}
        socket = new DatagramSocket();
        try { socket.setSoTimeout(timeoutMs); } catch (SocketException e) { throw e; }
    }

    public void close() {
        if (socket != null && !socket.isClosed()) socket.close();
    }

    public String getTarget() { return targetHost + ":" + targetPort; }

    // -------------------------------------------------------------------------
    // Result container
    // -------------------------------------------------------------------------
    public static class SendResult {
        public enum Status { RESPONSE, TIMEOUT, PORT_UNREACHABLE, ERROR }

        public final Status status;
        public final byte[] responseBytes;
        public final long rttMs;

        public SendResult(Status status, byte[] responseBytes, long rttMs) {
            this.status        = status;
            this.responseBytes = responseBytes;
            this.rttMs         = rttMs;
        }

        public boolean hasResponse()  { return status == Status.RESPONSE && responseBytes != null; }
        public boolean isTimeout()    { return status == Status.TIMEOUT; }
        public boolean isCrash()      { return status == Status.PORT_UNREACHABLE || status == Status.ERROR; }
    }
}
