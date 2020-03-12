package com.enovationgroup.dane.dns;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TLSARecord;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DaneResolver {

    private final DnsResolver resolver;
    private final MxResolver mxResolver;

    /**
     * MX record lookup should be secure via DNSSEC,
     * else there really is no point in using DANE:
     * without DNSSEC the mail-servers found via MX record lookups
     * can point to attacker mail-servers with valid DANE records.
     */
    private final boolean resolveMxSecure;

    public DaneResolver(DnsResolver resolver) {
        this(resolver, true);
    }

    public DaneResolver(DnsResolver resolver, boolean resolveMxSecure) {
        this.resolver = resolver;
        this.mxResolver = new MxResolver(resolver);
        this.resolveMxSecure = resolveMxSecure;
    }

    public LinkedHashMap<String, Collection<DaneRecord>> resolveDaneRecords(String mxDomain) throws IOException {

        var emailServers =  mxResolver.resolveMxDomains(mxDomain, resolveMxSecure);
        if (emailServers.isEmpty()) {
            log.debug("Found no email-servers for domain {}.", mxDomain);
        } else {
            log.debug("Email-servers for domain {}: {}.", mxDomain, emailServers);
        }
        // Email-servers have a priority. Preserve this order with the linked hashmap.
        var daneEmailServerRecords = new LinkedHashMap<String, Collection<DaneRecord>>();
        try {
            for (String emailServer : emailServers) {
                var daneRecords = resolveDaneRecord(mxDomain, emailServer);
                if (!daneRecords.isEmpty()) {
                    log.debug("Adding {} dane-record(s) for email-server {}.", daneRecords.size(), emailServer);
                    daneEmailServerRecords.put(emailServer, daneRecords);
                }
            }
        } catch (IOException e) {
            log.info("Secure DANE records lookup for domain {} and servers [{}] failed: {}", mxDomain, emailServers, e.toString());
        }
        return daneEmailServerRecords;
    }

    public Collection<DaneRecord> resolveDaneRecord(String mxDomain, String emailServer) throws IOException {
        return toDaneRecords(mxDomain, emailServer, resolveTlsaRecords(emailServer));
    }

    public Collection<DaneRecord> toDaneRecords(String mxDomain, String emailServer, Message response) {

        var records = response.getSectionArray(Section.ANSWER);
        if (records == null || records.length == 0) {
            return Collections.emptySet();
        }
        var daneRecords = new HashSet<DaneRecord>();
        for (Record r : records) {
            var daneRecord = toDaneRecord(mxDomain, emailServer, r);
            if (daneRecord != null) {
                daneRecords.add(daneRecord);
            }
        }
        return daneRecords;
    }

    protected DaneRecord toDaneRecord(String mxDomain, String emailServer, Record r) {

        if (!(r instanceof TLSARecord)) {
            return null;
        }
        DaneRecord daneRecord = null;
        try {
            daneRecord = DaneRecord.createFrom(mxDomain, emailServer, (TLSARecord) r);
        } catch (Exception e) {
            log.warn("Unexpected invalid value in TLSA record.", e);
        }
        return daneRecord;
    }

    public Message resolveTlsaRecords(String emailServer) throws IOException {

        log.debug("Resolving TLSA records for domain {}", emailServer);
        var queryRecord = Record.newRecord(Name.fromConstantString(toQualifiedMailDomain(emailServer)), Type.TLSA, DClass.IN);
        return resolver.resolveSecure(emailServer, Message.newQuery(queryRecord));
    }

    public String toQualifiedMailDomain(String emailServer) {

        String qdomain = emailServer;
        if (!qdomain.startsWith("_")) {
            qdomain = "_25._tcp." + qdomain;
        }
        if (!qdomain.endsWith(".")) {
            qdomain += ".";
        }
        return qdomain;
    }

}
