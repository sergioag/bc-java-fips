package org.bouncycastle.crypto;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.fips.FipsOperationError;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.util.Arrays;

/**
 * Basic class describing a secret key implementation. The key will be zeroized explicitly on
 * garbage collection and is protected from being shared between approved an un-approved threads.
 * <p>
 * <b>Note</b>: it the module is run under the SecurityManager only invokers with CryptoServicesPermission.FIPS_MODE_EXPORT_SECRET_KEY
 * permission can successfully call the getKeyBytes() method.
 * </p>
 */
public final class SymmetricSecretKey
    implements SymmetricKey, Destroyable
{
    private final boolean approvedModeOnly;

    private int hashCode;
    private Algorithm algorithm;
    private byte[] bytes;

    /**
     * Base constructor.
     *
     * @param algorithm the algorithm this secret key is associated with.
     * @param bytes     the bytes representing the key's value.
     */
    public SymmetricSecretKey(Algorithm algorithm, byte[] bytes)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.hashCode = calculateHashCode();
        this.bytes = bytes.clone();
    }

    /**
     * Base constructor for a specific algorithm associated with a parameter set.
     *
     * @param parameterSet the parameter set with the algorithm this secret key is associated with.
     * @param bytes        the bytes representing the key's value.
     */
    public SymmetricSecretKey(Parameters parameterSet, byte[] bytes)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = parameterSet.getAlgorithm();
        this.hashCode = calculateHashCode();
        this.bytes = bytes.clone();
    }

    /**
     * Return the algorithm this secret key is for.
     *
     * @return the secret keys algorithm.
     */
    public Algorithm getAlgorithm()
    {
        checkDestroyed();
        return algorithm;
    }

    private void zeroize()
    {
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = 0;
        }
        bytes = null;
        algorithm = null;
        hashCode = 0;
    }

    /**
     * Return the bytes representing this keys value.
     * <p>
     * See CryptoServicesPermission.FIPS_MODE_EXPORT_SECRET_KEY for the permission associated with this method.
     *
     * @return the bytes making up this key.
     */
    public byte[] getKeyBytes()
    {
        checkApprovedOnlyModeStatus();

        final SecurityManager securityManager = System.getSecurityManager();

        if (securityManager != null)
        {
            securityManager.checkPermission(Permissions.CanOutputSecretKey);
        }

        byte[] clone = org.bouncycastle.util.Arrays.clone(bytes);

        checkDestroyed();

        return clone;
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof SymmetricSecretKey))
        {
            return false;
        }

        SymmetricSecretKey other = (SymmetricSecretKey)o;

        other.checkApprovedOnlyModeStatus();

        return (this.algorithm != null && this.algorithm.equals(other.algorithm))
            && org.bouncycastle.util.Arrays.constantTimeAreEqual(bytes, other.bytes);
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        checkApprovedOnlyModeStatus();

        int result = getAlgorithm().hashCode();
        result = 31 * result + Arrays.hashCode(bytes);
        return result;
    }

    final void checkApprovedOnlyModeStatus()
    {
        if (approvedModeOnly != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsOperationError("attempt to use key created in " + ((approvedModeOnly) ? "approved mode" : "unapproved mode") + " in alternate mode.");
        }
    }

    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    public void destroy()
        throws DestroyFailedException
    {
        if (hasBeenDestroyed.compareAndSet(false, true))
        {
            zeroize();
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    private void checkDestroyed()
    {
        if (this.isDestroyed())
        {
            throw new IllegalStateException("key has been destroyed");
        }
    }
}
