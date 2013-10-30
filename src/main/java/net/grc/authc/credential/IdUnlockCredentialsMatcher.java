package net.grc.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

import java.util.Arrays;

/**
 * Validates a SQRL Identity Unlock request.
 * <p/>
 * Prerequisite: validated SQRL Credentials.
 */
public class IdUnlockCredentialsMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        SQRLCredentials sqrlCredentials = (SQRLCredentials) token.getCredentials();

        // user did not supply ID unlock credentials
        if (!(sqrlCredentials instanceof IdUnlockCredentials)) return false;

        SQRLAnonymousPrincipal authInfoPrincipal = ((SQRLAnonymousPrincipal) token.getPrincipal())
                .findMatchingPrincipal(info.getPrincipals());

        // user's ID is not locked
        if (!(authInfoPrincipal instanceof IdLockPrincipal)) return false;

        IdLockPrincipal lockPrincipal = (IdLockPrincipal) authInfoPrincipal;
        IdUnlockCredentials unlockCredentials = (IdUnlockCredentials) sqrlCredentials;

        // TODO read only buffer array is null
        return checkvalid(unlockCredentials.getVerificationHmac().array(),
                lockPrincipal.getIdLockKeyVerifier().array(),
                unlockCredentials.getNut().array());
    }

    protected boolean checkvalid(byte[] clientVerificationHmac, byte[] keyVerifier, byte[] sharedNut) {
        return Arrays.equals(clientVerificationHmac, hmac(keyVerifier, sharedNut));
    }

    protected byte[] hmac(byte[] a, byte[] b) {
        return new byte[0];
    }
}
