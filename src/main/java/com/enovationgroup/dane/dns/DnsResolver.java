package com.enovationgroup.dane.dns;

import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.SimpleResolver;

import java.io.IOException;
import java.net.UnknownHostException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DnsResolver {

    private final SimpleResolver resolver;
    private final SimpleResolver resolverInsecure;

    public DnsResolver() {
        this(null, 0);
    }

    public DnsResolver(String dnsHost, int dnsPort) {
        try {
            this.resolver = createResolver(dnsHost, dnsPort, true);
            this.resolverInsecure = createResolver(dnsHost, dnsPort, false);
        } catch (Exception e) {
            var msg = "Unable to create DNS resolver using server " + dnsHost + ":" + dnsPort;
            log.error(msg, e);
            throw new RuntimeException(msg, e);
        }
    }

    public void setTCP(boolean tcpOnly) {
        getResolver(true).setTCP(tcpOnly);
        getResolver(false).setTCP(tcpOnly);
    }

    protected SimpleResolver createResolver(String dnsHost, int dnsPort, boolean secure) throws UnknownHostException {

        SimpleResolver sr;
        if (dnsHost == null || "0".equals(dnsHost) || "default".equals(dnsHost)) {
            sr = new SimpleResolver();
        } else {
            sr = new SimpleResolver(dnsHost);
        }
        if (dnsPort > 0) {
            sr.setPort(dnsPort);
        }
        /*
         * The "ExtendedFlags.DO" ensures that DNSSEC is requested and used by unbound.
         * Usage of this flag can be seen at
         * https://github.com/ibauersachs/dnssecjava/blob/master/src/main/java/org/jitsi/dnssec/validator/ValidatingResolver.java
         *
         * Compare output of insecure dig command:
         * dig zorgmail.nl. TXT IN
         * with output of secure dig command:
         * dig +dnssec +tcp zorgmail.nl. TXT IN -p 5353
         *
         * The line showing the flags the output, e.g.:
         * ;; flags: qr rd ra ad; ...
         * will have "ad" for "authenticated data" when DNSSEC is used and answer is "secure".
         */
        if (secure) {
            sr.setEDNS(0, 0, ExtendedFlags.DO, null);
        }
        return sr;
    }

    protected SimpleResolver getResolver(boolean secure) {
        return (secure ? resolver : resolverInsecure);
    }

    public String toQualifiedDomain(String domain) {
        return (domain.endsWith(".") ? domain : domain + ".");
    }

    protected Message resolveSecure(String domain, Message query) throws IOException {
        return resolve(domain, query, true);
    }

    protected Message resolveInsecure(String domain, Message query) throws IOException {
        return resolve(domain, query, false);
    }

    protected Message resolve(String domain, Message query, boolean secure) throws IOException {

        var response = getResolver(secure).send(query);
        if (response.getRcode() != Rcode.NOERROR) {
            /*
             * Rcode.SERVFAIL can indicate a failure to connect from our side to the DNS server,
             * or it can indicate a DNS server that is not properly configured or just unavailable.
             * It can also indicate that there is no secure/DNSSEC response available.
             * In any case, there is no reliable way to determine if we should retry the lookup
             * because there is a network error on our side.
             */
            throw new IOException("Invalid return code " + Rcode.string(response.getRcode()) + " for DNS record lookup of domain " + domain);
        }
        if (secure && !response.getHeader().getFlag(Flags.AD)) {
            /*
             * This will probably never happen since unbound should report Rcode.SERVFAIL
             * when a requested secure lookup fails.
             */
            throw new IOException("Secure DNS record lookup failed for domain " + domain);
        }
        return response;
    }

}
