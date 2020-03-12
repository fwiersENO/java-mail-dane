package com.enovationgroup.dane.dns;

import org.xbill.DNS.TLSARecord;

import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Optional;

import lombok.Data;
import lombok.ToString;

/**
 * Describes a DANE / TLSA record, see also
 * https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities
 */
@Data
public class DaneRecord {

    public enum CertificateUsage {
        /** CA constraint */
        PKIX_TA(0),
        /** Service certificate constraint */
        PKIX_EE(1),
        /** Trust Anchor Assertion */
        DANE_TA(2),
        /** Domain issued certificate */
        DANE_EE(3);

        private final int value;
        private CertificateUsage(int value) { this.value = value; }
        public int value() { return value; }
        public static Optional<CertificateUsage> find(int value) {
            return Arrays.stream(CertificateUsage.values()).filter(e -> e.value() == value).findFirst();
        }
    }

    public enum Selector {
        /** Select the entire certificate for matching. */
        FULL(0),
        /** Select the public key for certificate matching. */
        PUBLIC_KEY(1);

        private final int value;
        private Selector(int value) { this.value = value; }
        public int value() { return value; }
        public static Optional<Selector> find(int value) {
            return Arrays.stream(Selector.values()).filter(e -> e.value() == value).findFirst();
        }
    }

    public enum MatchingType {
        /** The entire information selected is present in the certificate association data. */
        FULL(0),
        /** Do a SHA-256 hash of the selected data. */
        SHA_256(1),
        /** Do a SHA-512 hash of the selected data. */
        SHA_512(2);

        private final int value;
        private MatchingType(int value) { this.value = value; }
        public int value() { return value; }
        public static Optional<MatchingType> find(int value) {
            return Arrays.stream(MatchingType.values()).filter(e -> e.value() == value).findFirst();
        }
    }

    private String mxDomain;
    private String domain;
    private CertificateUsage certificateUsage;
    private Selector selector;
    private MatchingType matchingType;
    @ToString.Exclude
    private byte[] certificateAssociationData;

    public boolean isSupported() {

        // Certificate Usage 0 and 1 are not allowed for use with email servers (port 25). See RFC7672 3.1.3 (https://tools.ietf.org/html/rfc7672#section-3.1.3) for details.
        if (getCertificateUsage() == CertificateUsage.PKIX_TA || getCertificateUsage() == CertificateUsage.PKIX_EE) {
            return false;
        }
        return true;
    }

    /**
     * Can throw {@link NoSuchElementException} when values are missing or not correct.
     */
    public static DaneRecord createFrom(String mxDomain, String domain, TLSARecord tlsaRecord) {

        var daneRecord = new DaneRecord();
        daneRecord.setMxDomain(mxDomain);
        daneRecord.setDomain(domain);
        daneRecord.setCertificateUsage(CertificateUsage.find(tlsaRecord.getCertificateUsage()).get());
        daneRecord.setSelector(Selector.find(tlsaRecord.getSelector()).get());
        daneRecord.setMatchingType(MatchingType.find(tlsaRecord.getMatchingType()).get());
        daneRecord.setCertificateAssociationData(tlsaRecord.getCertificateAssociationData());
        return daneRecord;
    }
}
