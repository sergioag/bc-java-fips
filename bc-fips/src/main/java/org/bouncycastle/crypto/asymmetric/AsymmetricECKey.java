package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for Elliptic Curve (EC) keys.
 */
public abstract class AsymmetricECKey
    implements AsymmetricKey
{
    private final boolean    approvedModeOnly;

    private Algorithm algorithm;
    private ECDomainParameters domainParameters;

    AsymmetricECKey(Algorithm algorithm, ECDomainParameters domainParameters)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
    }

    AsymmetricECKey(Algorithm algorithm, ECDomainParametersID domainParameterID)
    {
        this(algorithm, ECDomainParametersIndex.lookupDomainParameters(domainParameterID));
    }

    AsymmetricECKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
    {
        this(algorithm, ECDomainParameters.decodeCurveParameters(algorithmIdentifier));
    }

    /**
      * Return the algorithm this Elliptic Curve key is for.
      *
      * @return the key's algorithm.
      */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the Elliptic Curve domain parameters associated with this key.
     *
     * @return the EC domain parameters for the key.
     */
    public ECDomainParameters getDomainParameters()
    {
        return domainParameters;
    }

    protected void zeroize()
    {
        this.algorithm = null;
        this.domainParameters = null;
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
