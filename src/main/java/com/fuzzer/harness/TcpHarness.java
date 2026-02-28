package com.fuzzer.harness;

import java.io.*;
import java.net.*;
import java.util.Arrays;

/**
 * TcpHarness — DNS over TCP transport driver.
 *
 * DNS over TCP (RFC 1035 §4.2.2) differs from UDP in two critical ways:
 *
 *   1. MESSAGE FRAMING: Each DNS message is prefixed with a 2-byte big-endian
 *      length field indicating the number of bytes that follow.
 *
 *      [len_hi][len_lo][DNS message bytes...]
 *
 *      This framing is absent in UDP — each UDP datagram IS the message.
 *      Parsers that handle both transports have two separate framing paths,
 *      and the TCP framing path is typically less tested.
 *
 *   2. CONNECTION STATE: TCP is stateful. The server maintains per-connection
 *      state. Abrupt disconnects, half-open connections, and connection floods
 *      are attack surfaces that don't exist in UDP.
 *
 * AXFR (RFC 5936) requires TCP — zone transfers are too large for UDP.
 * The AXFR response is a multi-message sequence:
 *   [SOA record] → [zone records...] → [SOA record again]
 * All on the same TCP connection.
 *
 * Attack surfaces this harness enables:
 *   - Length field manipulation (claim more/fewer bytes than follow)
 *   - Partial writes (send length but not the full message)
 *   - Connection state abuse (send AXFR mid-connection after another query)
 *   - Large message injection (length field near 65535)
 *   - Malformed AXFR sequences (wrong SOA, missing terminator)
 */
public class TcpHarness implements AutoCloseable {

    private final String targetHost;
    private final int    targetPort;
    private final int    timeoutMs;
    private final int    connectTimeoutMs;

    private Socket socket;
    private DataInputStream  in;
    private DataOutputStream out;

    private static final int MAX_DNS_MSG = 65535; // RFC 1035 max message size
    private static final int READ_BUFFER  = 65535 + 2; // +2 for length prefix

    public TcpHarness(String targetHost, int targetPort, int timeoutMs) throws IOException {
        this.targetHost       = targetHost;
        this.targetPort       = targetPort;
        this.timeoutMs        = timeoutMs;
        this.connectTimeoutMs = Math.min(timeoutMs, 3000);
        connect();
    }

    // -------------------------------------------------------------------------
    // Connection management
    // -------------------------------------------------------------------------

    private void connect() throws IOException {
        socket = new Socket();
        socket.connect(new InetSocketAddress(targetHost, targetPort), connectTimeoutMs);
        socket.setSoTimeout(timeoutMs);
        socket.setTcpNoDelay(true);       // disable Nagle — we control framing manually
        socket.setKeepAlive(true);
        in  = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
    }

    /**
     * Reconnect after a crash or connection reset.
     * Called by orchestrator after detecting a hard crash.
     */
    public void reconnect() throws IOException {
        close();
        Thread.sleep2(500); // brief pause before reconnect
        connect();
    }

    // -------------------------------------------------------------------------
    // Send / Receive
    // -------------------------------------------------------------------------

    /**
     * Send a DNS message over TCP using standard RFC 1035 framing:
     *   [2-byte big-endian length][message bytes]
     *
     * Returns the server's response (also length-prefixed, stripped on read).
     * Returns a TIMEOUT result if no response within timeoutMs.
     * Returns PORT_UNREACHABLE if the connection is reset (hard crash signal).
     */
    public SendResult send(byte[] message) throws IOException {
        return sendWithLength(message, message.length); // standard framing
    }

    /**
     * Send with an explicit length field — may differ from actual message length.
     * Used by mutators to inject length-field mismatches.
     *
     * @param message      The DNS message bytes to write
     * @param claimedLength The value to write in the 2-byte length prefix
     */
    public SendResult sendWithLength(byte[] message, int claimedLength) throws IOException {
        try {
            // Write 2-byte length prefix
            out.writeByte((claimedLength >> 8) & 0xFF);
            out.writeByte(claimedLength & 0xFF);
            // Write message body
            out.write(message);
            out.flush();

            return readResponse();

        } catch (SocketTimeoutException e) {
            return new SendResult(SendResult.Status.TIMEOUT, null, timeoutMs);
        } catch (SocketException e) {
            // Connection refused or reset — hard crash signal
            return new SendResult(SendResult.Status.PORT_UNREACHABLE, null, 0);
        }
    }

    /**
     * Send only the length prefix, then no message bytes.
     * Tests servers that block waiting for the promised bytes.
     */
    public SendResult sendLengthOnly(int length) throws IOException {
        try {
            out.writeByte((length >> 8) & 0xFF);
            out.writeByte(length & 0xFF);
            out.flush();
            return readResponse();
        } catch (SocketTimeoutException e) {
            return new SendResult(SendResult.Status.TIMEOUT, null, timeoutMs);
        } catch (SocketException e) {
            return new SendResult(SendResult.Status.PORT_UNREACHABLE, null, 0);
        }
    }

    /**
     * Send raw bytes with NO length prefix.
     * Tests what happens when a server receives non-framed data on the DNS TCP port.
     */
    public SendResult sendRaw(byte[] rawBytes) throws IOException {
        try {
            out.write(rawBytes);
            out.flush();
            return readResponse();
        } catch (SocketTimeoutException e) {
            return new SendResult(SendResult.Status.TIMEOUT, null, timeoutMs);
        } catch (SocketException e) {
            return new SendResult(SendResult.Status.PORT_UNREACHABLE, null, 0);
        }
    }

    /**
     * Read a length-prefixed DNS response from the server.
     * Reads the 2-byte length, then reads exactly that many bytes.
     */
    private SendResult readResponse() throws IOException {
        long start = System.currentTimeMillis();

        // Read 2-byte length prefix
        int hi = in.read();
        int lo = in.read();
        if (hi < 0 || lo < 0) {
            // EOF — server closed connection
            return new SendResult(SendResult.Status.PORT_UNREACHABLE, null, 0);
        }
        int msgLen = (hi << 8) | lo;

        if (msgLen <= 0 || msgLen > MAX_DNS_MSG) {
            // Malformed length from server
            return new SendResult(SendResult.Status.ERROR,
                    new byte[]{(byte)hi, (byte)lo}, System.currentTimeMillis() - start);
        }

        // Read exactly msgLen bytes
        byte[] response = new byte[msgLen];
        int read = 0;
        while (read < msgLen) {
            int n = in.read(response, read, msgLen - read);
            if (n < 0) {
                return new SendResult(SendResult.Status.PORT_UNREACHABLE, null, 0);
            }
            read += n;
        }

        long rtt = System.currentTimeMillis() - start;
        return new SendResult(SendResult.Status.RESPONSE, response, rtt);
    }

    /**
     * Read multiple responses from a single connection.
     * Used for AXFR — server sends SOA + records + SOA, all length-prefixed,
     * on the same connection.
     *
     * Reads until:
     *   - A second SOA record is seen (normal AXFR termination)
     *   - Timeout occurs
     *   - Connection closes
     *   - maxMessages is reached (safety limit)
     */
    public MultiResponse readAxfrResponse(int maxMessages) throws IOException {
        MultiResponse result = new MultiResponse();
        long start = System.currentTimeMillis();

        for (int i = 0; i < maxMessages; i++) {
            // Check timeout
            if (System.currentTimeMillis() - start > timeoutMs) {
                result.timedOut = true;
                break;
            }

            try {
                SendResult r = readResponse();
                if (r.status == SendResult.Status.RESPONSE && r.responseBytes != null) {
                    result.messages.add(r.responseBytes);
                    result.totalBytes += r.responseBytes.length;
                    // Check if this is a second SOA (AXFR terminator)
                    if (result.messages.size() > 1 && isSOAResponse(r.responseBytes)) {
                        result.complete = true;
                        break;
                    }
                } else if (r.status == SendResult.Status.PORT_UNREACHABLE) {
                    result.connectionClosed = true;
                    break;
                } else if (r.status == SendResult.Status.TIMEOUT) {
                    result.timedOut = true;
                    break;
                }
            } catch (SocketTimeoutException e) {
                result.timedOut = true;
                break;
            }
        }

        result.rttMs = System.currentTimeMillis() - start;
        return result;
    }

    /**
     * Check if a DNS response contains a SOA record in the answer section.
     * SOA QTYPE = 6 (0x0006).
     * Minimal check: look for QTYPE=SOA in the response answer section.
     */
    private boolean isSOAResponse(byte[] response) {
        if (response.length < 12) return false;
        // ANCOUNT is at bytes 6-7
        int ancount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);
        if (ancount == 0) return false;
        // Walk past QNAME to find answer section — simplified: scan for 0x00 0x06 pattern
        for (int i = 12; i < response.length - 1; i++) {
            if (response[i] == 0x00 && response[i+1] == 0x06) {
                return true; // SOA type found
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Liveness
    // -------------------------------------------------------------------------

    /**
     * Liveness probe — send a standard A query over TCP and expect a response.
     * Confirms the server is accepting TCP connections and responding.
     */
    public boolean isAlive(byte[] validQuery) {
        try {
            SendResult result = send(validQuery);
            return result.status == SendResult.Status.RESPONSE;
        } catch (IOException e) {
            return false;
        }
    }

    public void close() {
        try { if (socket != null && !socket.isClosed()) socket.close(); }
        catch (IOException ignored) {}
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }

    public String getTarget() { return targetHost + ":" + targetPort; }

    // -------------------------------------------------------------------------
    // Thread.sleep wrapper (avoids checked exception noise)
    // -------------------------------------------------------------------------
    private static class Thread {
        static void sleep2(long ms) {
            try { java.lang.Thread.sleep(ms); } catch (InterruptedException ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // Result containers
    // -------------------------------------------------------------------------

    public static class SendResult {
        public enum Status { RESPONSE, TIMEOUT, PORT_UNREACHABLE, ERROR }

        public final Status  status;
        public final byte[]  responseBytes;
        public final long    rttMs;

        public SendResult(Status status, byte[] responseBytes, long rttMs) {
            this.status        = status;
            this.responseBytes = responseBytes;
            this.rttMs         = rttMs;
        }

        public boolean hasResponse()  { return status == Status.RESPONSE && responseBytes != null; }
        public boolean isTimeout()    { return status == Status.TIMEOUT; }
        public boolean isCrash()      { return status == Status.PORT_UNREACHABLE; }
        public boolean isError()      { return status == Status.ERROR; }
    }

    public static class MultiResponse {
        public java.util.List<byte[]> messages = new java.util.ArrayList<>();
        public boolean complete         = false; // true = got second SOA
        public boolean timedOut         = false;
        public boolean connectionClosed = false;
        public long    rttMs            = 0;
        public long    totalBytes       = 0;

        public int messageCount() { return messages.size(); }
        public boolean hasAny()   { return !messages.isEmpty(); }
    }
}
