# java-mail-dane

SMTP DANE validation with `javax.mail`

Java 11 based implementation of [DANE](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities) validation.

The main implementation of DANE validation is performed in [TrustManagerDane](./src/main/java/com/enovationgroup/dane/smtp/TrustManagerDane.java).

The correctness of this implementation has not been verified, we are looking for feedback.

A unit-test that covers most of the validation is available at [DaneCertValidationTest](./src/test/java/com/enovationgroup/dane/smtp/DaneCertValidationTest.java)

DANE validation requires the use of a DNSSEC-capable dns-server (e.g. [unbound](https://nlnetlabs.nl/projects/unbound/about/)).
Once a DNSSEC-capable dns-server is configured in [DaneConnect](./src/main/java/com/enovationgroup/dane/DaneConnect.java)
(you will need to update the class to do this), a DANE validation-test can be executed using the commands:

    mvn clean verify
    mvn exec:java -Dexec.args="xs4all.nl"
	