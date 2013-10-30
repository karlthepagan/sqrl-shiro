package net.grc.authc.credential;

import java.nio.ByteBuffer;

/**
 * Id Lock credentials represent the request to unlock or replace (or delete?) a SQRL identity.
 */
public interface IdUnlockCredentials {
    ByteBuffer getNut();
    ByteBuffer getVerificationHmac();
}
