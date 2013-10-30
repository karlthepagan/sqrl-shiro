package net.grc.authc;

import net.grc.authc.credential.SQRLAnonymousPrincipal;
import net.grc.authc.credential.SQRLCredentials;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.shiro.authc.HostAuthenticationToken;

import java.net.URI;
import java.util.List;

/**
 * Encapsulates an authentication attempt. "consolidation of an account's principals and supporting
 * credentials submitted by a user during an authentication attempt"
 */
public class SQRLToken implements HostAuthenticationToken {
    /**
     * DRAFT standard
     */
    private static final String SQRL_VERSION = "0";

    private final SQRLAnonymousPrincipal principal;
    private final SQRLCredentials credentials;
    private final String remoteHost;

    public SQRLToken(URI challenge, String signature, String remoteHost) {
        this(challenge, URLEncodedUtils.parse(challenge, "UTF-8"), signature, remoteHost);
    }

    protected SQRLToken(URI challenge, List<NameValuePair> challengeQuery, String signature, String remoteHost) {
        this.remoteHost = remoteHost;

        String ver = null;
        String key = null;
        String sqrlD = null;

        for (NameValuePair param : challengeQuery) {
            if ("sqrlver".equals(param.getName())) {
                if (ver == null) {
                    ver = param.getValue();
                }
            } else if ("sqrlkey".equals(param.getName())) {
                if (key == null) {
                    key = param.getValue();
                }
            } else if ("d".equals(param.getName())) {
                if (sqrlD == null) {
                    sqrlD = param.getValue();
                }
            }
        }

        if (!ver.equals(SQRL_VERSION)) throw new IllegalArgumentException("sqrlver=" + ver);
        this.principal = new SQRLAnonymousPrincipal(challenge, key, Integer.parseInt(sqrlD), ver);
        this.credentials = new SQRLCredentials(challenge, signature, ver);
    }

    SQRLToken(SQRLAnonymousPrincipal principal, SQRLCredentials credentials, String remoteHost) {
        this.remoteHost = remoteHost;
        this.principal = principal;
        this.credentials = credentials;
    }

    @Override
    public String getHost() {
        return remoteHost;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }
}
