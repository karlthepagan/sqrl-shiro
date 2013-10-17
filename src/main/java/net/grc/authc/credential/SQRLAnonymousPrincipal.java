package net.grc.authc.credential;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Encapsulates the information defining a SQRL id: the realm (aka domain) and public key
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

    final String sqrlRealm;
    final ByteBuffer sqrlkey;

    public SQRLAnonymousPrincipal(URI challenge, String key, int d, String sqrlver) {
        if(sqrlver == null) throw new IllegalArgumentException("sqrlver=null");
        if(!sqrlver.equals(SQRL_VERSION)) throw new IllegalArgumentException("sqrlver="+sqrlver);

        if(key == null) throw new IllegalArgumentException("key==null");

        Base64 b64 = new Base64(true);
        this.sqrlkey = ByteBuffer.wrap(b64.decode(key));

        sqrlRealm = validateURI(challenge, d);
    }

    public static String validateURI(URI uri, int d) {
        if(uri == null) throw new IllegalArgumentException("challenge=null");
        if(d < 0) throw new IllegalArgumentException("d="+d);

        uri = uri.normalize();
        String asciiString = uri.toASCIIString();
        if(uri.getHost() == null) {
            throw new IllegalArgumentException(asciiString + " does not appear to have a hostname");
        }
        Matcher m = URL_HOST_UPPER.matcher(uri.getHost());
        if(m.find()) {
            throw new IllegalArgumentException(asciiString + " hostname contains uppercase");
        }
        String asciiPath = uri.getRawPath();
        if(d > asciiPath.length()) {
            throw new IllegalArgumentException(asciiString + " path is shorter than d (" + d + ")");
        }
        String schemeHost = uri.getScheme() + "://" + uri.getHost();

        m = URL_LOWERCASE_ESCAPES.matcher(asciiPath);
        if(m.find()) {
            throw new IllegalArgumentException(asciiString + " path contains lowercase escapes");
        }
        m = URL_ESCAPES.matcher(asciiPath);
        while(m.find()) {
            String escaped = new String(Character.toChars(Integer.parseInt(m.group(1),16)));
            Matcher m2 = URL_UNRESERVED.matcher(escaped);
            if(m2.find()) {
                throw new IllegalArgumentException(asciiString + " path escapes unreserved characters");
            }

        }
        return schemeHost + asciiPath.substring(0,d);
    }

    /**
     * the SQRL standards version in use
     */
    public String getVersion() {
        return SQRL_VERSION;
    }

    /**
     * SQRL realms (or domains) are the concatenation of the scheme, the FQDN, and an optional fragment of the rquest path
     */
    public String getRealm() {
        return sqrlRealm;
    }

    /**
     * An Ed25519 public key which is based on the realm
     */
    public ByteBuffer getPublicKey() {
        return sqrlkey.asReadOnlyBuffer();
    }

    @Override
    public boolean equals(Object o) {
        if(o == null || !(o instanceof SQRLAnonymousPrincipal)) {
            return false;
        }

        SQRLAnonymousPrincipal other = (SQRLAnonymousPrincipal)o;
        return other.sqrlRealm.equals(this.sqrlRealm)
                && Arrays.equals(other.sqrlkey.array(),this.sqrlkey.array());

        // TODO wrapped buffer equals may be inconsistent
    }
}
