package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.general.LMS;

/**
 * Leighton-Micali Hash-Based Signatures (LMS) keys.
 */
public abstract class AsymmetricLMSKey
    implements AsymmetricKey
{
    private final boolean    approvedModeOnly;

    private Algorithm algorithm;

    protected final int L;

    AsymmetricLMSKey(int L)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = LMS.ALGORITHM;
        this.L = L;
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

    /**
     * Return the number of levels (L) associated with the key.
     *
     * @return L.
     */
    public int getL()
    {
        return L;
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
