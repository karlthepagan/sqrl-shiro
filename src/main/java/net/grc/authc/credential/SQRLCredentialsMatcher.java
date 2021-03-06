package net.grc.authc.credential;

import net.grc.authc.SQRLToken;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

import java.nio.charset.Charset;

/**
 * Verifies that the credentials supplied in the token match the token's principals.
 */
public class SQRLCredentialsMatcher implements CredentialsMatcher {
    /**
     * DRAFT standard
     */
    private static final String SQRL_VERSION = "0";

    private static final Charset UTF8 = Charset.forName("UTF-8");

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (!(token instanceof SQRLToken)) {
            return false;
        }

        SQRLAnonymousPrincipal sqrlId = (SQRLAnonymousPrincipal) token.getPrincipal();
        SQRLCredentials sqrlCredentials = (SQRLCredentials) token.getCredentials();

        // TODO draft standard is very strict about not accepting future versions
        if (!SQRL_VERSION.equals(sqrlId.getVersion()))
            throw new IllegalArgumentException("sqrlId.version=" + sqrlId.getVersion());
        if (!SQRL_VERSION.equals(sqrlCredentials.getVersion()))
            throw new IllegalArgumentException("sqrlCredentials.version=" + sqrlCredentials.getVersion());

        // TODO ByteBuffer.array() offset not checked
        return checkvalid(sqrlCredentials.sqrlsig.array(),
                sqrlCredentials.getChallenge().getBytes(UTF8),
                sqrlId.sqrlkey.array());
    }

    protected boolean checkvalid(byte[] sig, byte[] msg, byte[] pub) {
        return false;
    }
}
