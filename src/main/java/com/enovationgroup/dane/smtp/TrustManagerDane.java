package com.enovationgroup.dane.smtp;

import org.apache.commons.lang3.StringUtils;

import com.enovationgroup.dane.dns.DaneRecord;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import javax.net.ssl.X509TrustManager;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class TrustManagerDane implements X509TrustManager {

    private final Collection<DaneRecord> daneRecords;

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // NOOP
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {

        if (certs == null || certs.length == 0) {
            throw new CertificateException("Certificate chain is empty.");
        }
        if (StringUtils.isEmpty(authType)) {
            throw new CertificateException("Key exchange algorithm is empty.");
        }
        // Check on dane 3 1 1 first (DANE_EE), then 2 1 1 (DANE_TA) if available.
        var daneDomainRecords = daneRecords.stream()
            .filter(e -> e.getCertificateUsage() == DaneRecord.CertificateUsage.DANE_EE)
            .collect(Collectors.toList());
        if (validateDane(certs, daneDomainRecords)) {
            return;
        }
        // DANE_TA can only be used if another intermediate (trust anchor) certificate is also send by SMTP server.
        if (certs.length > 1) {
            var daneTrustedAnchorRecords = daneRecords.stream()
                    .filter(e -> e.getCertificateUsage() == DaneRecord.CertificateUsage.DANE_TA)
                    .collect(Collectors.toList());
            if (validateDane(certs, daneTrustedAnchorRecords)) {
                return;
            }
        }
        // DANE validation for presented server certificates failed.
        var r = daneRecords.stream().findFirst().get();
        throw new CertificateException("No valid DANE certificates found for domain " + r.getDomain() + " / " + r.getMxDomain());
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    boolean validateDane(X509Certificate[] certs, Collection<DaneRecord> records) {

        if (records.isEmpty()) {
            return false;
        }
        var found = records.stream().filter(r -> isValidDane(certs, r)).findFirst();
        if (log.isDebugEnabled() && found.isPresent()) {
            log.debug("Found match for dane record {}", found.get());
        }
        return found.isPresent();
    }

    boolean isValidDane(X509Certificate[] certs, DaneRecord record) {

        if (!record.isSupported()) {
            return false;
        }
        try {
            if (record.getCertificateUsage() == DaneRecord.CertificateUsage.DANE_EE) {
                return validateDaneEE(certs, record);
            } else if (record.getCertificateUsage() == DaneRecord.CertificateUsage.DANE_TA) {
                return validateDaneTA(certs, record);
            }
        } catch (Exception e) {
            log.error("DANE validation failed unexpectedly for domain {} / {}.", record.getDomain(), record.getMxDomain(), e);
        }
        return false;
    }

    boolean validateDaneEE(X509Certificate[] certs, DaneRecord record) throws NoSuchAlgorithmException, CertificateEncodingException {

        // Validate DANE record against the domain certificate.
        return validateDaneCert(certs[0], record);
    }

    boolean validateDaneCert(X509Certificate cert, DaneRecord record) throws NoSuchAlgorithmException, CertificateEncodingException {

        MessageDigest digester = null;
        if (record.getMatchingType() == DaneRecord.MatchingType.SHA_256) {
            digester = MessageDigest.getInstance("SHA-256");
        } else if (record.getMatchingType() == DaneRecord.MatchingType.SHA_512) {
            digester = MessageDigest.getInstance("SHA-512");
        }
        byte[] certData;
        if (record.getSelector() == DaneRecord.Selector.PUBLIC_KEY) {
            certData = cert.getPublicKey().getEncoded();
        } else {
            // DaneRecord.Selector.FULL
            certData = cert.getEncoded();
        }
        if (digester != null) {
            certData = digester.digest(certData);
        }
        return Arrays.equals(certData, record.getCertificateAssociationData());
    }

    boolean validateDaneTA(X509Certificate[] certs, DaneRecord record) throws NoSuchAlgorithmException, CertificateEncodingException {

        // Validate DANE record against trust anchor (first intermediate certificate).
        if (!validateDaneCert(certs[1], record)) {
            return false;
        }
        // Validate chain. Validation up to a root CA is not required according to specs.
        // Expire date validations are usually skipped for SMTP (cert.checkValidity()).
        for (int i = 0; i < certs.length - 1; i++) {
            boolean verified = false;
            try {
                certs[i].verify(certs[i+1].getPublicKey());
                verified = true;
            } catch (SignatureException | InvalidKeyException e) {
                log.warn("Invalid certificate chain for domain {} / {}: {}", record.getDomain(), record.getMxDomain(), e.toString());
            } catch (Exception e) {
                log.warn("Unable to verify certificate chain for domain {} / {}: {}", record.getDomain(), record.getMxDomain(), e);
            }
            if (!verified) {
                return false;
            }
        }
        return true;
    }

}
