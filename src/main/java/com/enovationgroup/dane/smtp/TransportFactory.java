package com.enovationgroup.dane.smtp;

import com.enovationgroup.dane.dns.DaneRecord;
import com.sun.mail.smtp.SMTPTransport;

import java.util.Collection;
import java.util.Properties;

import javax.mail.Session;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import lombok.SneakyThrows;

public class TransportFactory {

    @SneakyThrows
    public static SMTPTransport buildTransport(String mailHost, Collection<DaneRecord> daneRecords, boolean smtpDebug) {

        Properties props = new Properties();

        props.put("mail.smtp.host", mailHost);
        props.put("mail.smtp.port", 25);
        props.put("mail.smtp.connectiontimeout", 3_000);
        props.put("mail.smtp.timeout", 10_000);
        // props.put("mail.smtp.localaddress", "bind-address");
        props.put("mail.smtp.ssl.socketFactory", createSslSocketFactory(new TrustManagerDane(daneRecords), null));
        props.put("mail.smtp.auth", false); // disable basic-auth
        props.put("mail.smtp.starttls.enable", true);
        props.put("mail.smtp.starttls.required", true);

        var session = Session.getInstance(props);
        if (smtpDebug) {
            SmtpWireLog.registerWireLog(session);
        }
        return (SMTPTransport) session.getTransport("smtp");
    }

    public static SSLSocketFactory createSslSocketFactory(TrustManager trustManager, KeyManager keyManager) {
        return createSslSocketFactory("TLS", trustManager, keyManager);
    }

    @SneakyThrows
    public static SSLSocketFactory createSslSocketFactory(String protocol, TrustManager trustManager, KeyManager keyManager) {

        SSLSocketFactory socketFactory;
        SSLContext sslcontext = SSLContext.getInstance(protocol);
        sslcontext.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, null);
        socketFactory = sslcontext.getSocketFactory();
        return socketFactory;
    }

}
