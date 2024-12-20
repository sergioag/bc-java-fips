package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for Edwards Curve Diffie-Hellman (XDH) keys.
 */
public abstract class AsymmetricXDHKey
    implements AsymmetricKey
{
    private final boolean    approvedModeOnly;

    private Algorithm algorithm;

    AsymmetricXDHKey(Algorithm algorithm)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
    }

    /**
      * Return the algorithm this Edwards Curve key is for.
      *
      * @return the key's algorithm.
      */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    protected void zeroize()
    {
        this.algorithm = null;
    }

    protected final boolean isThreadCorrectMode()
    {
        return approvedModeOnly == CryptoServicesRegistrar.isInApprovedOnlyMode();
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (!isThreadCorrectMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }
}
