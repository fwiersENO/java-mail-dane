package com.enovationgroup.dane.dns;

import org.apache.commons.lang3.StringUtils;
import org.xbill.DNS.DClass;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import com.enovationgroup.dane.MailUtil;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MxResolver {

    private final DnsResolver resolver;

    public MxResolver(DnsResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Secure (DNSSEC) MX records domain lookup, see also {@link #resolveMxDomains(String, boolean)}.
     */
    public List<String> resolveMxDomains(String domain) throws IOException {
        return resolveMxDomains(domain, true);
    }

    /**
     * Return list of target MX domains in lowercase sorted by priority.
     * @param secure If false, use insecure DNS lookup.
     */
    public List<String> resolveMxDomains(String domain, boolean secure) throws IOException {

        var records = resolveMxRecords(domain, secure).getSectionArray(Section.ANSWER);
        if (records == null || records.length == 0) {
            return Collections.emptyList();
        }
        return Arrays.stream(records)
            .filter(r -> r instanceof MXRecord)
            .map(r -> (MXRecord) r)
            .sorted(Comparator.comparing(MXRecord::getPriority))
            .map(MXRecord::getTarget)
            .filter(Objects::nonNull)
            .map(r -> r.toString(true))
            .map(StringUtils::strip)
            .filter(StringUtils::isNotEmpty)
            .map(MailUtil::lowerCase)
            .collect(Collectors.toList());
    }

    public Message resolveMxRecords(String domain, boolean secure) throws IOException {

        log.debug("Resolving MX records for domain {}", domain);
        var queryRecord = Record.newRecord(Name.fromConstantString(resolver.toQualifiedDomain(domain)), Type.MX, DClass.IN);
        return (secure ?
                resolver.resolveSecure(domain, Message.newQuery(queryRecord)) :
                    resolver.resolveInsecure(domain, Message.newQuery(queryRecord)));
    }

}
