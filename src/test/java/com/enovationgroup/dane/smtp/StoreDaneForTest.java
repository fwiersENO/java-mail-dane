package com.enovationgroup.dane.smtp;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.enovationgroup.dane.dns.DaneRecord;
import com.enovationgroup.dane.dns.DaneResolver;
import com.enovationgroup.dane.dns.DnsResolver;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Map;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class StoreDaneForTest {

    @Test
    public void dummy() {
      log.debug("Not really tests here, just something to store DANE related information that can be used for testing.");
    }

    /**
     * update these variables to point to a DNSSEC capable DNS resolver (e.g. unbound).
     */
    final static String dnsHost = "localhost";
    final static int dnsPort = 5353;
    final static boolean useDnsTcpOnly = true;

    static DaneResolver resolver;

    @BeforeAll
    public static void setupResolver() {

        var dnsResolver = new DnsResolver(dnsHost, dnsPort);
        if (useDnsTcpOnly) {
            dnsResolver.setTCP(true);
        }
        resolver = new DaneResolver(dnsResolver, false);
        log.debug("Resolving DNS with host {}:{}", dnsHost, dnsPort);
    }

    //@Test
    @SneakyThrows
    public void storeZorgmailDane() {

        var record = getFirst(resolver.resolveDaneRecords("zorgmail.nl"));
        var outFile = Paths.get("relay.zorgmail.nl.tlsa.json").toAbsolutePath();
        storeDaneRecord(outFile, record);
    }

    @SneakyThrows
    void storeDaneRecord(Path outFile, DaneRecord record) {

        var mapper = new ObjectMapper().addMixIn(DaneRecord.class, DaneRecordMixin.class);
        log.info("Storing dane-record at {}", outFile);
        mapper.writer().withoutAttribute("supported").writeValue(outFile.toFile(), record);
        log.info("Reading dane-record at {}", outFile);
        DaneRecord daneIn = mapper.readValue(outFile.toFile(), DaneRecord.class);
        Assertions.assertEquals(record, daneIn);
    }

    private <T> T getFirst(Map<String, Collection<T>> c) {
        return c.get(c.keySet().stream().findFirst().get()).stream().findFirst().get();
    }

    interface DaneRecordMixin {
        @JsonIgnore
        boolean isSupported();
    }

}
