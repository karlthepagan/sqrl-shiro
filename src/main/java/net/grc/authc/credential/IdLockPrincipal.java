package net.grc.authc.credential;

import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * The principal for a SQRL id which can be securely replaced later.
 * <p/>
 * Id Lock basics:
 * * DHKA definition: DHKA(Pub-1,SK-2) == DHKA(Pub-2,SK-1)
 * * Pub-X = EC_MakePublic(SK-X)
 * <p/>
 * Initiation:
 * * Key Verifier = DHKA(Pub-IdLock,SK-Request)
 * * Public Unlock Key = Pub-Request = EC_MakePublic(SK-Request)
 * <p/>
 * Reassociation: after authentication client request or is challenged to replace their key, and supplied Public Unlock Key
 * * Key Verifier = DHKA(Pub-Request,SK-IdLock)
 */
public class IdLockPrincipal extends SQRLAnonymousPrincipal {

    private final ByteBuffer idLockPublicKey;
    private final ByteBuffer idLockKeyVerifier;

    public IdLockPrincipal(URI challenge, String key, int d, String sqrlver,
                           String xSqrlKeyVerifier, String xSqrlPublicUnlockKey) {
        super(challenge, key, d, sqrlver);

        Base64 b64 = new Base64(true);
        idLockPublicKey = ByteBuffer.wrap(b64.decode(xSqrlPublicUnlockKey));
        idLockKeyVerifier = ByteBuffer.wrap(b64.decode(xSqrlKeyVerifier));
    }

    IdLockPrincipal(String sqrlDomain, byte[] sqrlkey, byte[] idLockPublic, byte[] idLockVerifier) {
        super(sqrlDomain, sqrlkey);

        this.idLockPublicKey = ByteBuffer.wrap(idLockVerifier);
        this.idLockKeyVerifier = ByteBuffer.wrap(idLockVerifier);
    }

    public ByteBuffer getIdLockPublicKey() {
        return idLockPublicKey.asReadOnlyBuffer();
    }

    public ByteBuffer getIdLockKeyVerifier() {
        return idLockKeyVerifier.asReadOnlyBuffer();
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = (hash * 31) ^ Arrays.hashCode(idLockPublicKey.array());
        hash = (hash * 31) ^ Arrays.hashCode(idLockKeyVerifier.array());
        return hash;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !o.getClass().equals(IdLockPrincipal.class)) {
            return false;
        }

        return fieldsEqual((IdLockPrincipal) o);
    }

    protected boolean fieldsEqual(IdLockPrincipal other) {
        return super.fieldsEqual(other)
                && Arrays.equals(other.idLockPublicKey.array(), idLockPublicKey.array())
                && Arrays.equals(other.idLockKeyVerifier.array(), idLockKeyVerifier.array());
    }
}