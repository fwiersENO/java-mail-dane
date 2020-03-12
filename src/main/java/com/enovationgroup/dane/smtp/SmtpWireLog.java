package com.enovationgroup.dane.smtp;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import javax.mail.Session;

/**
 * Helper class to send smtp debug logging to Slf4j logger with category <tt>smtp.wire</tt>.
 */
public class SmtpWireLog extends FilterOutputStream {

    private static final Logger log = LoggerFactory.getLogger("smtp.wire");
    private static final Charset PRINT_CHARSET = StandardCharsets.UTF_8;

    // Empty lines are sometimes meaningfull.
    private boolean logEmptyLine;

    public SmtpWireLog() {
        super(new ByteArrayOutputStream());
    }

    protected ByteArrayOutputStream getBout() {
        return (ByteArrayOutputStream) out;
    }

    protected void logBout() {

        if (getBout().size() > 0) {
            if (log.isDebugEnabled()) {
                var msgBytes = getBout().toByteArray();
                if ((msgBytes.length == 2 && msgBytes[0] == 13 && msgBytes[1] == 10) // windows
                        || (msgBytes.length == 1 && msgBytes[0] == 10)) { // linux
                    if (logEmptyLine) {
                        log.debug(StringUtils.EMPTY);
                        logEmptyLine = false;
                    } else {
                        logEmptyLine = true;
                    }
                } else {
                    var msg = StringUtils.stripEnd(new String(msgBytes, PRINT_CHARSET), null);
                    log.debug(msg);
                    logEmptyLine = false;
                }
            }
            getBout().reset();
        }
    }

    @Override
    public void flush() throws IOException {
        logBout();
    }

    @Override
    public void write(int b) throws IOException {
        // Do no call super.write, that will result in stackoverflow.
        getBout().write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        super.write(b, off, len);
    }

    /**
     * If logger category <tt>smtp.wire</tt> is set to <tt>debug</tt>,
     * enables wire-logging of the SMTP transfer in the given session.
     */
    public static void registerWireLog(Session session) {

        if (log.isDebugEnabled()) {
            session.setDebugOut(new PrintStream(new SmtpWireLog(), true, PRINT_CHARSET));
            session.setDebug(true);
        }
    }

}
