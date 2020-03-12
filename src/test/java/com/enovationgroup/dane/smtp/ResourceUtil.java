package com.enovationgroup.dane.smtp;

import org.apache.commons.io.IOUtils;

import com.enovationgroup.dane.dns.DaneRecord;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ResourceUtil {

    public static ObjectMapper mapper = new ObjectMapper();

    private ResourceUtil() {}

    @SneakyThrows
    public static DaneRecord loadRecord(String resourceName) {
        return mapper.readValue(loadResource(resourceName), DaneRecord.class);
    }

    @SneakyThrows
    public static X509Certificate loadCert(String resourceName) {

        var in = new ByteArrayInputStream(loadResource(resourceName));
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        return (X509Certificate) fact.generateCertificate(in);
    }

    @SneakyThrows
    public static byte[] loadResource(String resourceName) {

        try (var in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName)) {
            return IOUtils.toByteArray(in);
        }
    }

    public static ByteArrayInputStream openResource(String resourceName) {

        ByteArrayInputStream in;
        try (var inResource = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName)) {
            in = new ByteArrayInputStream(IOUtils.toByteArray(inResource));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read resource file " + resourceName + ": " + e);
        }
        if (in.available() == 0) {
            log.warn("Resource file {} is empty.", resourceName);
        }
        return in;
    }

}
