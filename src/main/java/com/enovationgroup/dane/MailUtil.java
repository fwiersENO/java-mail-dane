package com.enovationgroup.dane;

import java.util.Locale;

public class MailUtil {

    public static String lowerCase(String s) {
        return (s == null ? null : s.toLowerCase(Locale.US));
    }

}
