package com.enovationgroup.dane.smtp;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.enovationgroup.dane.dns.DaneRecord;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.List;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

/**
 * Resources used were created using methods in StoreDaneForTest
 * and using command:
 * <br><tt>openssl s_client -starttls smtp -host relay.zorgmail.nl -port 25 -prexit -showcerts</tt>
 * <br>Each shown certificate was stored as PEM in src/test/resources/*.crt
 * <br>Certificate information can be shown using the command:
 * <br><tt>openssl x509 -in filename.crt -text -noout</tt>
 */
@Slf4j
public class DaneCertValidationTest {

    // TODO: test "FULL" DANE validations (DaneRecord.Selector.FULL and DaneRecord.MatchingType.FULL)

    ObjectMapper mapper = new ObjectMapper();

    @Test
    @SneakyThrows
    public void validatePublicKey() {

        var record = ResourceUtil.loadRecord("certs-zorgmail-relay/relay.zorgmail.nl.tlsa.json");
        // assume 3 1 1
        Assertions.assertEquals(DaneRecord.CertificateUsage.DANE_EE, record.getCertificateUsage());
        Assertions.assertEquals(DaneRecord.Selector.PUBLIC_KEY, record.getSelector());
        Assertions.assertEquals(DaneRecord.MatchingType.SHA_256, record.getMatchingType());
        var cert = ResourceUtil.loadCert("certs-zorgmail-relay/0-relay.zorgmail.nl.crt");
        Assertions.assertNotNull(cert);
        var digester = MessageDigest.getInstance("SHA-256");
        var hash = digester.digest(cert.getPublicKey().getEncoded());
        Assertions.assertArrayEquals(record.getCertificateAssociationData(), hash);
    }

    @Test
    @SneakyThrows
    public void validatePublicKeyTm() {

        var record = ResourceUtil.loadRecord("certs-zorgmail-relay/relay.zorgmail.nl.tlsa.json");
        var cert = ResourceUtil.loadCert("certs-zorgmail-relay/0-relay.zorgmail.nl.crt");
        var tm = new TrustManagerDane(List.of(record));
        try {
            tm.checkServerTrusted(List.of(cert).toArray(new X509Certificate[0]), "RSA");
        } catch (Exception e) {
            Assertions.fail("Expected valid DANE public key.", e);
        }
    }

    @Test
    @SneakyThrows
    public void validatePublicKeyTmFail() {

        var record = ResourceUtil.loadRecord("certs-zorgmail-relay/relay.zorgmail.nl.tlsa.json");
        var cert = ResourceUtil.loadCert("certs-secumailer/0-gateway.secumailer.eu.crt");
        var tm = new TrustManagerDane(List.of(record));
        try {
            tm.checkServerTrusted(List.of(cert).toArray(new X509Certificate[0]), "RSA");
            Assertions.fail("Expected verification failure for wrong public key.");
        } catch (Exception e) {
            log.debug("Got expected exception: {}", e.toString());
        }
    }

    @Test
    @SneakyThrows
    public void validatePublicKeySha512() {

        var record = ResourceUtil.loadRecord("certs-zivver-smtp/smtp.zivver.com.tlsa.json");
        // assume 3 1 2
        Assertions.assertEquals(DaneRecord.CertificateUsage.DANE_EE, record.getCertificateUsage());
        Assertions.assertEquals(DaneRecord.Selector.PUBLIC_KEY, record.getSelector());
        Assertions.assertEquals(DaneRecord.MatchingType.SHA_512, record.getMatchingType());
        var cert = ResourceUtil.loadCert("certs-zivver-smtp/0-smtp.zivver.com.crt");
        Assertions.assertNotNull(cert);
        var digester = MessageDigest.getInstance("SHA-512");
        var hash = digester.digest(cert.getPublicKey().getEncoded());
        Assertions.assertArrayEquals(record.getCertificateAssociationData(), hash);
    }

    @Test
    @SneakyThrows
    public void validatePublicKeySha512Tm() {

        var record = ResourceUtil.loadRecord("certs-zivver-smtp/smtp.zivver.com.tlsa.json");
        var cert = ResourceUtil.loadCert("certs-zivver-smtp/0-smtp.zivver.com.crt");
        var tm = new TrustManagerDane(List.of(record));
        try {
            tm.checkServerTrusted(List.of(cert).toArray(new X509Certificate[0]), "RSA");
        } catch (Exception e) {
            Assertions.fail("Expected valid DANE public key SHA512.", e);
        }
    }

    @Test
    @SneakyThrows
    public void validateTrustedAnchor() {

        // First ensure normal 3 1 1 record is valid.
        var record = ResourceUtil.loadRecord("certs-heemskerk-vmx/vmx01.prolocation.nl.tlsa.json");
        // assume 3 1 2
        Assertions.assertEquals(DaneRecord.CertificateUsage.DANE_EE, record.getCertificateUsage());
        Assertions.assertEquals(DaneRecord.Selector.PUBLIC_KEY, record.getSelector());
        Assertions.assertEquals(DaneRecord.MatchingType.SHA_256, record.getMatchingType());
        var cert = ResourceUtil.loadCert("certs-heemskerk-vmx/0-vmx01.prolocation.nl.crt");
        Assertions.assertNotNull(cert);
        var digester = MessageDigest.getInstance("SHA-256");
        var hash = digester.digest(cert.getPublicKey().getEncoded());
        Assertions.assertArrayEquals(record.getCertificateAssociationData(), hash);

        // Validate againt trust anchor.
        record = ResourceUtil.loadRecord("certs-heemskerk-vmx/vmx01.prolocation.nl.2.tlsa.json");
        Assertions.assertEquals(DaneRecord.CertificateUsage.DANE_TA, record.getCertificateUsage());
        Assertions.assertEquals(DaneRecord.Selector.PUBLIC_KEY, record.getSelector());
        Assertions.assertEquals(DaneRecord.MatchingType.SHA_256, record.getMatchingType());
        cert = ResourceUtil.loadCert("certs-heemskerk-vmx/1-usertrust.crt"); // the intermediate trust anchor
        hash = digester.digest(cert.getPublicKey().getEncoded());
        Assertions.assertArrayEquals(record.getCertificateAssociationData(), hash);

        // Validate chain, according to specs, validation up to a CA is not required.
        var certServer = ResourceUtil.loadCert("certs-heemskerk-vmx/0-vmx01.prolocation.nl.crt");
        var certIntermediate = ResourceUtil.loadCert("certs-heemskerk-vmx/1-usertrust.crt");
        var certBase = ResourceUtil.loadCert("certs-heemskerk-vmx/2-usertrust.crt");
        certServer.verify(certIntermediate.getPublicKey());
        certIntermediate.verify(certBase.getPublicKey());

        try {
            certIntermediate.verify(certServer.getPublicKey());
            Assertions.fail("Expected verification failure.");
        } catch (Exception e) {
            log.debug("Got expected exception: {}", e.toString());
        }

        // For full validation, also check validaty (X509TrustManager). Just for reference, not a test.
        try {
            certServer.checkValidity(); // for 3 1 1 and 2 1 1
            certIntermediate.checkValidity(); // for 2 1 1
            log.debug("Certificates are still valid.");
        } catch (Exception e) {
            log.debug("Don't care about {}", e.toString());
        }
    }

    @Test
    @SneakyThrows
    public void validateTrustedAnchorTm() {

        // Validate againt trust anchor.
        var recordTA = ResourceUtil.loadRecord("certs-heemskerk-vmx/vmx01.prolocation.nl.2.tlsa.json");
        var certServer = ResourceUtil.loadCert("certs-heemskerk-vmx/0-vmx01.prolocation.nl.crt");
        var certIntermediate = ResourceUtil.loadCert("certs-heemskerk-vmx/1-usertrust.crt");
        var certBase = ResourceUtil.loadCert("certs-heemskerk-vmx/2-usertrust.crt");
        var certs = List.of(certServer, certIntermediate, certBase).toArray(new X509Certificate[0]);
        var tm = new TrustManagerDane(List.of(recordTA));
        try {
            tm.checkServerTrusted(certs, "RSA");
        } catch (Exception e) {
            Assertions.fail("Expected valid DANE trust anchor.", e);
        }
        // Fail when certificate chain is invalid
        certs = List.of(certBase, certIntermediate, certServer).toArray(new X509Certificate[0]);
        try {
            tm.checkServerTrusted(certs, "RSA");
            Assertions.fail("Expecting exception when chain is invalid.");
        } catch (Exception e) {
            Assertions.assertTrue(e.getMessage().startsWith("No valid DANE certificates found"));
        }
        // Fail when certificate chain is not available
        try {
            tm.checkServerTrusted(List.of(certServer).toArray(new X509Certificate[0]), "RSA");
            Assertions.fail("Expecting exception when no chain is available for trust anchor verification.");
        } catch (Exception e) {
            Assertions.assertTrue(e.getMessage().startsWith("No valid DANE certificates found"));
        }
        // Test prefer validation against DANE_EE
        var recordEE = ResourceUtil.loadRecord("certs-heemskerk-vmx/vmx01.prolocation.nl.tlsa.json");
        tm = new TrustManagerDane(List.of(recordTA, recordEE));
        try {
            tm.checkServerTrusted(List.of(certServer).toArray(new X509Certificate[0]), "RSA");
        } catch (Exception e) {
            Assertions.fail("Expected preferred validation with DANE_EE record.", e);
        }
    }

}
