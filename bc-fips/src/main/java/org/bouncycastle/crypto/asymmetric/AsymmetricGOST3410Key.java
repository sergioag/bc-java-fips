package org.bouncycastle.crypto.asymmetric;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for keys for GOST R 34.10-1994 and GOST R 34.10-2001.
 *
 * @param <T> domain parameters for the particular key type.
 */
public abstract class AsymmetricGOST3410Key<T>
    implements AsymmetricKey
{
    protected static final Set ecAcceptable = new HashSet();
    protected static final Set fpAcceptable = new HashSet();

    static
    {
        ecAcceptable.add(CryptoProObjectIdentifiers.gostR3410_2001);
        ecAcceptable.add(CryptoProObjectIdentifiers.gostR3410_2001DH);
        ecAcceptable.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        ecAcceptable.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);
        ecAcceptable.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
        ecAcceptable.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);

        fpAcceptable.add(CryptoProObjectIdentifiers.gostR3410_94);
    }

    private Algorithm algorithm;
    private GOST3410Parameters<T> domainParameters;

    AsymmetricGOST3410Key(Algorithm algorithm, GOST3410Parameters<T> domainParameters)
    {
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
    }

    AsymmetricGOST3410Key(Algorithm algorithm, Set acceptable, AlgorithmIdentifier algorithmIdentifier)
    {
        if (!acceptable.contains(algorithmIdentifier.getAlgorithm()))
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + algorithmIdentifier.getAlgorithm());
        }

        this.algorithm = algorithm;
        this.domainParameters = (GOST3410Parameters<T>)decodeDomainParameters(algorithmIdentifier);
    }

    private static GOST3410Parameters decodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
    {
        if (KeyUtils.isNotNull(algorithmIdentifier.getParameters()))
        {
            GOST3410PublicKeyAlgParameters params = GOST3410PublicKeyAlgParameters.getInstance(algorithmIdentifier.getParameters());

            return new GOST3410Parameters<GOST3410DomainParameters>(params.getPublicKeyParamSet(), params.getDigestParamSet(), params.getDigestParamSet());
        }

        return null;
    }

    /**
      * Return the algorithm this GOST R 34.10 key is for.
      *
      * @return the key's algorithm.
      */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the domain parameters associated with this key.These will either
     * be for GOST R 34.10-1994 or GOST R 34.10-2001 depending on the key type.
     *
     * @return the GOST3410 domain parameters.
     */
    public GOST3410Parameters<T> getParameters()
    {
        return domainParameters;
    }

    protected final boolean isThreadCorrectMode()
    {
        return !CryptoServicesRegistrar.isInApprovedOnlyMode();
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (!isThreadCorrectMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }

    protected void zeroize()
    {
        this.algorithm = null;
        this.domainParameters = null;
    }
}
