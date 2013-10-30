package net.grc.authc.credential;

import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Encapsulates the information defining a SQRL id: the domain and public key
 */
public class SQRLAnonymousPrincipal {
    /**
     * DRAFT standard
     */
    private static final String SQRL_VERSION = "0";
    static final Pattern URL_LOWERCASE_ESCAPES = Pattern.compile("%([a-f][0-9a-f]|[0-9][a-f])");
    static final Pattern URL_ESCAPES = Pattern.compile("(?i)%([0-9a-f]{2})");
    static final Pattern URL_UNRESERVED = Pattern.compile("[A-Za-z0-9_\\.~\\-]");
    static final Pattern URL_HOST_UPPER = Pattern.compile("[A-Z]");
    static final Pattern URL_DEFAULTPORT_QRL = Pattern.compile("^qrl://.*:80$");
    static final Pattern URL_DEFAULTPORT_SQRL = Pattern.compile("^sqrl://.*:443$");

    final String sqrlDomain;
    final ByteBuffer sqrlkey;

    public SQRLAnonymousPrincipal(URI challenge, String key, int d, String sqrlver) {
        if (sqrlver == null) throw new IllegalArgumentException("sqrlver=null");
        if (!sqrlver.equals(SQRL_VERSION)) throw new IllegalArgumentException("sqrlver=" + sqrlver);

        if (key == null) throw new IllegalArgumentException("key==null");

        Base64 b64 = new Base64(true);
        this.sqrlkey = ByteBuffer.wrap(b64.decode(key));

        sqrlDomain = validateURI(challenge, d);
    }

    /**
     * constructor appropriate for data storage layer
     */
    public SQRLAnonymousPrincipal(String sqrlDomain, byte[] sqrlkey) {
        this.sqrlDomain = sqrlDomain;
        this.sqrlkey = ByteBuffer.wrap(sqrlkey);
    }

    public static String validateURI(URI uri, int d) {
        // TODO extract to parser class

        // TODO discard the scheme from uri?
        // TODO d parameter is superceded by the pipe | path separator

        if (uri == null) throw new IllegalArgumentException("challenge=null");
        if (d < 0) throw new IllegalArgumentException("d=" + d);

        uri = uri.normalize();
        String asciiString = uri.toASCIIString();
        if (uri.getHost() == null) {
            throw new IllegalArgumentException(asciiString + " does not appear to have a hostname");
        }
        Matcher m = URL_HOST_UPPER.matcher(uri.getHost());
        if (m.find()) {
            throw new IllegalArgumentException(asciiString + " hostname contains uppercase");
        }
        String asciiPath = uri.getRawPath();
        if (d > asciiPath.length()) {
            throw new IllegalArgumentException(asciiString + " path is shorter than d (" + d + ")");
        }
        String schemeHost = uri.getScheme() + "://" + uri.getHost();

        m = URL_LOWERCASE_ESCAPES.matcher(asciiPath);
        if (m.find()) {
            throw new IllegalArgumentException(asciiString + " path contains lowercase escapes");
        }
        m = URL_ESCAPES.matcher(asciiPath);
        while (m.find()) {
            String escaped = new String(Character.toChars(Integer.parseInt(m.group(1), 16)));
            Matcher m2 = URL_UNRESERVED.matcher(escaped);
            if (m2.find()) {
                throw new IllegalArgumentException(asciiString + " path escapes unreserved characters");
            }

        }
        return schemeHost + asciiPath.substring(0, d);
    }

    /**
     * the SQRL standards version in use
     */
    public String getVersion() {
        return SQRL_VERSION;
    }

    /**
     * SQRL domains are the concatenation of the scheme, the FQDN, and an optional fragment of the rquest path
     */
    public String getDomain() {
        return sqrlDomain;
    }

    /**
     * An Ed25519 public key which is based on the domain
     */
    public ByteBuffer getPublicKey() {
        return sqrlkey.asReadOnlyBuffer();
    }

    @Override
    public int hashCode() {
        int hash = sqrlDomain.hashCode();
        hash = (hash * 31) ^ Arrays.hashCode(sqrlkey.array());
        return hash;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !o.getClass().equals(SQRLAnonymousPrincipal.class)) {
            return false;
        }

        return fieldsEqual((SQRLAnonymousPrincipal) o);
    }

    public SQRLAnonymousPrincipal findMatchingPrincipal(Iterable principals) {
        for (Object o : principals) {
            if (o instanceof SQRLAnonymousPrincipal
                    && fieldsEqual((SQRLAnonymousPrincipal) o)) {
                return (SQRLAnonymousPrincipal) o;
            }
        }
        return null;
    }

    protected boolean fieldsEqual(SQRLAnonymousPrincipal other) {
        return other.sqrlDomain.equals(this.sqrlDomain)
                && Arrays.equals(other.sqrlkey.array(), this.sqrlkey.array());

        // TODO wrapped buffer equals may be inconsistent
    }

    public static final Comparator ANY_SQRL_ID = new Comparator() {
        @Override
        public int compare(Object o1, Object o2) {
            if (!(o1 instanceof SQRLAnonymousPrincipal)) return 1;
            if (!(o2 instanceof SQRLAnonymousPrincipal)) return -1;

            SQRLAnonymousPrincipal s1 = (SQRLAnonymousPrincipal) o1;
            SQRLAnonymousPrincipal s2 = (SQRLAnonymousPrincipal) o2;

            int delta = s1.getDomain().compareTo(s2.getDomain());
            if (delta == 0) {
                delta = Integer.compare(
                        Arrays.hashCode(s1.sqrlkey.array()), // TODO array null for read only buffer
                        Arrays.hashCode(s2.sqrlkey.array()));
            }
            return delta;
        }
    };

    public static final Comparator ANONYMOUS_SQRL_ID = new Comparator() {
        @Override
        public int compare(Object o1, Object o2) {
            if (!o1.getClass().equals(SQRLAnonymousPrincipal.class)) return 1;
            if (!o2.getClass().equals(SQRLAnonymousPrincipal.class)) return -1;

            return ANY_SQRL_ID.compare(o1, o2);
        }
    };
}
