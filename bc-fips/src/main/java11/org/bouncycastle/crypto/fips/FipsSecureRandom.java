package org.bouncycastle.crypto.fips;

import java.security.DrbgParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.util.EntropyUtil;

/**
 * Base class for DRBG/RNG SecureRandom implementations that use FIPS approved algorithms.
 */
public final class FipsSecureRandom
    extends SecureRandom
{
    private final SecureRandom randomSource;
    private final String algorithmName;
    private final DRBG drbg;
    private final boolean predictionResistant;

    FipsSecureRandom(SecureRandom randomSource, String algorithmName, DRBG drbg, EntropySource entropySource, boolean predictionResistant)
    {
        super(new Random11Spi(randomSource, drbg, entropySource, predictionResistant), new RandomProvider());
        this.randomSource = randomSource;
        this.algorithmName = algorithmName;
        this.drbg = drbg;
        this.predictionResistant = predictionResistant;
    }

    public void setSeed(long seed)
    {
        // this will happen when SecureRandom() is created
        if (drbg != null)
        {
            synchronized (drbg)
            {
                this.randomSource.setSeed(seed);
            }
        }
    }
    
    /**
     * Return the algorithm name
     */
    public String getAlgorithm()
    {
        return algorithmName;
    }

    public void nextBytes(byte[] bytes, byte[] additionalInput)
    {
        synchronized (drbg)
        {
            // check if a reseed is required...
            if (drbg.generate(bytes, additionalInput, predictionResistant) < 0)
            {
                drbg.reseed(null);
                drbg.generate(bytes, additionalInput, predictionResistant);
            }
        }
    }

    /**
     * Return the block size of the underlying DRBG
     *
     * @return number of bits produced each cycle.
     */
    public int getBlockSize()
    {
        return drbg.getBlockSize();
    }

    /**
     * Return true if the underlying DRBG is configured for prediction resistance.
     *
     * @return true if prediction resistance configured, false otherwise.
     */
    public boolean isPredictionResistant()
    {
        return predictionResistant;
    }

    /**
     * Return the personalization string used to create the DRBG.
     *
     * @return the the personalization string used to create the DRBG.
     */
    public byte[] getPersonalizationString()
    {
        return drbg.getPersonalizationString();
    }

    /**
     * Return the security strength of the DRBG.
     *
     * @return the security strength (in bits) of the DRBG.
     */
    public int getSecurityStrength()
    {
        return drbg.getSecurityStrength();
    }

    /**
     * Force a reseed.
     */
    public void reseed()
    {
        drbg.reseed(null);
    }

    /**
     * Force a reseed with additional input.
     *
     * @param additionalInput additional input to be used in conjunction with reseed.
     */
    public void reseed(byte[] additionalInput)
    {
        drbg.reseed(additionalInput);
    }

    private static class Random11Spi
        extends SecureRandomSpi
    {
        private final SecureRandom randomSource;
        private final DRBG drbg;
        private final EntropySource entropySource;
        private final boolean predictionResistant;

        Random11Spi(SecureRandom randomSource, DRBG drbg, EntropySource entropySource, boolean predictionResistant)
        {
            this.randomSource = randomSource;
            this.drbg = drbg;
            this.entropySource = entropySource;
            this.predictionResistant = predictionResistant;
        }

        @Override
        protected void engineSetSeed(byte[] seed)
        {
            synchronized (drbg)
            {
                if (randomSource != null)
                {
                    randomSource.setSeed(seed);
                }
            }
        }

        @Override
        protected void engineNextBytes(byte[] bytes, SecureRandomParameters params)
        {
            synchronized (drbg)
            {
                if (params instanceof DrbgParameters.NextBytes)
                {
                    DrbgParameters.NextBytes p = (DrbgParameters.NextBytes)params;
                    if (p.getStrength() > drbg.getSecurityStrength())
                    {
                        throw new IllegalArgumentException("maximum strength of DRBG is " + drbg.getSecurityStrength() + " bits");
                    }
                    if (p.getPredictionResistance() && !predictionResistant)
                    {
                        throw new IllegalArgumentException("prediction resistance not available");
                    }

                    if (bytes == null)
                    {
                        throw new NullPointerException("bytes cannot be null");
                    }
                    if (bytes.length != 0)
                    {
                        // check if a reseed is required...
                        if (drbg.generate(bytes, p.getAdditionalInput(), predictionResistant) < 0)
                        {
                            drbg.reseed(null);
                            drbg.generate(bytes, p.getAdditionalInput(), predictionResistant);
                        }
                    }
                }
                else
                {
                    throw new IllegalArgumentException("unrecognized DrbgParameters: " + params.getClass());
                }
            }
        }

        @Override
        protected void engineNextBytes(byte[] bytes)
        {
            synchronized (drbg)
            {
                if (bytes == null)
                {
                    throw new NullPointerException("bytes cannot be null");
                }
                if (bytes.length != 0)
                {
                    // check if a reseed is required...
                    if (drbg.generate(bytes, null, predictionResistant) < 0)
                    {
                        drbg.reseed(null);
                        drbg.generate(bytes, null, predictionResistant);
                    }
                }
            }
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes)
        {
            return EntropyUtil.generateSeed(entropySource, numBytes);
        }

        @Override
        protected void engineReseed(SecureRandomParameters params)
        {
            synchronized (drbg)
            {
                if (params instanceof DrbgParameters.Reseed)
                {
                    DrbgParameters.Reseed p = (DrbgParameters.Reseed)params;

                    if (p.getPredictionResistance() && !predictionResistant)
                    {
                        throw new IllegalArgumentException("prediction resistance not available");
                    }

                    drbg.reseed(p.getAdditionalInput());
                }
                else
                {
                    if (params != null)
                    {
                        throw new IllegalArgumentException("unrecognized DrbgParameters: " + params.getClass());
                    }

                    drbg.reseed(null);
                }
            }
        }

        @Override
        protected SecureRandomParameters engineGetParameters()
        {
            // this needs to be done lazily to avoid triggering early initialization of drbg
            return DrbgParameters.instantiation(
                            drbg.getSecurityStrength(),
                            predictionResistant ? DrbgParameters.Capability.PR_AND_RESEED : DrbgParameters.Capability.RESEED_ONLY,
                            drbg.getPersonalizationString());
        }
    }

    private static class RandomProvider
        extends Provider
    {
        RandomProvider()
        {
            super("BCFIPS_RNG", 1.0, "BCFIPS Secure Random Provider");
        }
    }
}
