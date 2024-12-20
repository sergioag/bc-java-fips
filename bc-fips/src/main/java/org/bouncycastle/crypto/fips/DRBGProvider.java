package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EntropySource;

interface DRBGProvider
{
    DRBG get(EntropySource entropySource);

    /**
     * Return the algorithm name for the DRBG implementation.
     *
     * @return an algorithm name describing the DRBG.
     */
    String getAlgorithmName();
}
