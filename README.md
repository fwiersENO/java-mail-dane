# java-mail-dane

SMTP DANE validation with `javax.mail`

Java 11 based implementation of [DANE](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities) validation.

The main implementation of DANE validation is performed in [TrustManagerDane](./src/main/java/com/enovationgroup/dane/smtp/TrustManagerDane.java).

The correctness of this implementation has not been verified, we are looking for feedback.

A unit-test that covers most of the validation is available at [DaneCertValidationTest](./src/test/java/com/enovationgroup/dane/smtp/DaneCertValidationTest.java)

DANE validation requires the use of a DNSSEC-capable dns-server (e.g. [unbound](https://nlnetlabs.nl/projects/unbound/about/), see also below).
Once a DNSSEC-capable dns-server is configured in [DaneConnect](./src/main/java/com/enovationgroup/dane/DaneConnect.java)
(you will need to update the class to do this), a DANE validation-test can be executed using the commands:

    mvn clean verify
    # Currently valid DANE
    mvn exec:java -Dexec.args="xs4all.nl"
    # Currenlty failing DANE validation
    mvn exec:java -Dexec.args="secumailer.eu"

The [TransportFactory](./src/main/java/com/enovationgroup/dane/smtp/TransportFactory.java) class sets a number of connection properties,
e.g. the mail-port to connect to. Update this class if needed, e.g. to set a bind-address (a.k.a local-address).

### DNSSEC with unbound in Docker

Start unbound with the command:

    docker run --rm --name unbound-dns -d -p 5353:53/udp -p 5353:53/tcp mvance/unbound:latest

Test the local unbound server with a command like:

    dig @127.0.0.1 -p 5353 internet.nl TXT IN

Note that the `dig any` option does not work with unbound, only a very limited amount of records will be shown.
