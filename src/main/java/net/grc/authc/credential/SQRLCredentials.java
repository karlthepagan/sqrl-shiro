package net.grc.authc.credential;

import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Encapsulates the authentication attempt
 */
public class SQRLCredentials {
    /**
     * DRAFT standard
     */
    private static final String SQRL_VERSION = "0";

    final String sqrlChallenge;
    final ByteBuffer sqrlsig;

    public SQRLCredentials(URI challenge, String signature, String sqrlver) {
        if(challenge == null) throw new IllegalArgumentException("challenge=null");
        if(signature == null) throw new IllegalArgumentException("signature=null");
        if(sqrlver == null) throw new IllegalArgumentException("sqrlver=null");
        if(!sqrlver.equals(SQRL_VERSION)) throw new IllegalArgumentException("sqrlver="+sqrlver);

        Base64 b64 = new Base64(true);
        this.sqrlsig = ByteBuffer.wrap(b64.decode(signature));
        this.sqrlChallenge = challenge.toString(); // TODO toASCIIString?
    }

    /**
     * the SQRL standards version in use
     */
    public String getVersion() {
        return SQRL_VERSION;
    }

    /**
     * the URL string used to
     */
    public String getChallenge() {
        return sqrlChallenge;
    }

    /**
     * An Ed25519 signature for this challenge
     */
    public ByteBuffer getSignature() {
        return sqrlsig.asReadOnlyBuffer();
    }

    @Override
    public boolean equals(Object o) {
        if(o == null || !(o instanceof SQRLCredentials)) {
            return false;
        }

        SQRLCredentials other = (SQRLCredentials)o;
        return sqrlChallenge.equals(other.sqrlChallenge)
                && Arrays.equals(sqrlsig.array(),other.sqrlsig.array());

        // TODO wrapped buffer equals may be inconsistent
    }
}
