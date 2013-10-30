package net.grc.authc.credential;

import java.nio.ByteBuffer;

/**
 * Created with IntelliJ IDEA.
 * Date: 10/29/13
 * Time: 7:22 PM
 * To change this template use File | Settings | File Templates.
 */
public interface IdLockCredentials {
    ByteBuffer getKeyVerifier();
    ByteBuffer getPublicUnlockKey();
}
