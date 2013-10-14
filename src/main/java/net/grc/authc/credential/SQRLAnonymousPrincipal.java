package net.grc.authc.credential;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Encapsulates the information defining a SQRL id: the realm (aka domain) and public key
 */
public class SQRLAnonymousPrincipal {
    /**
     * DRAFT standard
     */
    private static final String SQRL_VERSION = "0";

    final String sqrlRealm;
    final ByteBuffer sqrlkey;

    public SQRLAnonymousPrincipal(URI challenge, String key, int d, String sqrlver) {
        if(challenge == null) throw new IllegalArgumentException("challenge=null");
        if(key == null) throw new IllegalArgumentException("key==null");
        if(d < 0) throw new IllegalArgumentException("d="+d);
        if(sqrlver == null) throw new IllegalArgumentException("sqrlver=null");
        if(!sqrlver.equals(SQRL_VERSION)) throw new IllegalArgumentException("sqrlver="+sqrlver);

        Base64 b64 = new Base64(true);
        this.sqrlkey = ByteBuffer.wrap(b64.decode(key));

//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        baos.write();
        StringBuilder sb = new StringBuilder();
        sb.append(challenge.getScheme());
        sb.append("://");
        sb.append(challenge.getHost());
        if(d > 0) {
            String path = challenge.getPath();
            if(d > path.length()) {
                throw new IllegalArgumentException("d="+d+" > path.length()="+(path.length()));
            }
            sb.append(path.substring(0,d));
        }
        sqrlRealm = sb.toString();
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
