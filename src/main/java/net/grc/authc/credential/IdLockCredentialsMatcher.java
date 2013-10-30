package net.grc.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

/**
 * The Id Lock phase
 */
public class IdLockCredentialsMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        SQRLCredentials sqrlCredentials = (SQRLCredentials) token.getCredentials();

        // user did not supply ID lock credentials
        if (!(sqrlCredentials instanceof IdLockCredentials)) return false;

        SQRLAnonymousPrincipal authInfoPrincipal = ((SQRLAnonymousPrincipal) token.getPrincipal())
                .findMatchingPrincipal(info.getPrincipals());

        // user's ID is already locked
        if (authInfoPrincipal instanceof IdLockPrincipal) return false;

        // this requires that the SQRLCredentialsMatcher has also passed
        return true;
    }
}
