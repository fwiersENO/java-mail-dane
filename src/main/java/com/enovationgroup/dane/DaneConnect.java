package com.enovationgroup.dane;

import com.enovationgroup.dane.dns.DaneResolver;
import com.enovationgroup.dane.dns.DnsResolver;
import com.enovationgroup.dane.smtp.TransportFactory;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DaneConnect {

    /**
     * update these variables to point to a DNSSEC capable DNS resolver (e.g. unbound).
     */
    final static String dnsHost = "localhost";
    final static int dnsPort = 5353;
    final static boolean useDnsTcpOnly = true;

    public static void main(String[] args) {

        if (args == null || args.length < 1) {
            System.out.println("Provide one argument: the domain to examine and try a DANE connection.");
        }
        try {
            new DaneConnect().tryDaneConnnection(args[0]);
        } catch (Exception e) {
            log.error("Connection test failed.", e);
            e.printStackTrace();
        }
    }

    @SneakyThrows
    public boolean tryDaneConnnection(String domain) {

        var dnsResolver = new DnsResolver(dnsHost, dnsPort);
        if (useDnsTcpOnly) {
            dnsResolver.setTCP(true);
        }
        var resolver = new DaneResolver(dnsResolver, false);
        log.debug("Resolving DNS with host {}:{}", dnsHost, dnsPort);
        var daneMailServers = resolver.resolveDaneRecords(domain);
        if (daneMailServers.isEmpty()) {
            log.info("No email-servers found for domain {}", domain);
        }
        boolean connected = false;
        for (String emailServer : daneMailServers.keySet()) {
            try {
                var transport = TransportFactory.buildTransport(emailServer, daneMailServers.get(emailServer), true);
                try {
                    transport.connect();
                    transport.isConnected(); // send NOOP command.
                    connected = true;
                    log.info("DANE connection OK for {}", emailServer);
                } finally {
                    transport.close();
                }
            } catch (Exception e) {
                log.warn("Failed to connect to {}: {}", emailServer, e.toString());
            }
            if (connected) {
                break;
            }
        }
        return connected;
    }

}
