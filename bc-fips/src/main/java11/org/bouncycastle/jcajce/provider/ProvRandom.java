package org.bouncycastle.jcajce.provider;


import java.security.DrbgParameters;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class ProvRandom
    extends AsymmetricAlgorithmProvider
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider" + ".random.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("SecureRandom.DEFAULT", PREFIX + "DefSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final SecureRandom random;
                if (constructorParameter == null)
                {
                    random = provider.getDefaultSecureRandom();
                }
                else
                {
                    final SecureRandom entropySource = provider.getDefaultEntropySource();
                    DrbgParameters.Instantiation params = (DrbgParameters.Instantiation)constructorParameter;

                    random = provider.getProviderDefaultRandomBuilder()
                                        .fromEntropySource(entropySource, true)
                                        .setSecurityStrength(params.getStrength())
                                        .setPersonalizationString(params.getPersonalizationString())
                                        .build(entropySource.generateSeed((params.getStrength() / (2 * 8)) + 1),
                                            params.getCapability() == DrbgParameters.Capability.PR_AND_RESEED, Strings.toByteArray("Bouncy Castle FIPS Custom Default"));
                }

                if (random instanceof FipsSecureRandom)
                {
                    return new MySecureRandomSpi((FipsSecureRandom)random);
                }
                return new SecureRandomSpi()
                {
                    @Override
                    protected void engineSetSeed(byte[] bytes)
                    {
                        random.setSeed(bytes);
                    }

                    @Override
                    protected void engineNextBytes(byte[] bytes)
                    {
                        random.nextBytes(bytes);
                    }

                    @Override
                    protected byte[] engineGenerateSeed(int numBytes)
                    {
                        return random.generateSeed(numBytes);
                    }
                };
            }
        });

        provider.addAlgorithmImplementation("SecureRandom.NONCEANDIV", PREFIX + "NonceAndIVSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final SecureRandom entropySource = provider.getDefaultEntropySource();
                final FipsSecureRandom random;

                if (constructorParameter == null)
                {
                    random = provider.getProviderDefaultRandomBuilder()
                        .fromEntropySource(entropySource, true)
                        .setPersonalizationString(generatePersonalizationString())
                        .build(entropySource.generateSeed((provider.getProviderDefaultSecurityStrength() / (2 * 8)) + 1),
                            false, Strings.toByteArray("Bouncy Castle FIPS Provider Nonce/IV"));
                }
                else
                {
                    DrbgParameters.Instantiation params = (DrbgParameters.Instantiation)constructorParameter;

                    random = provider.getProviderDefaultRandomBuilder()
                        .fromEntropySource(entropySource, true)
                        .setSecurityStrength(params.getStrength())
                        .setPersonalizationString(params.getPersonalizationString())
                        .build(entropySource.generateSeed((params.getStrength() / (2 * 8)) + 1),
                            params.getCapability() == DrbgParameters.Capability.PR_AND_RESEED,
                            Strings.toByteArray("Bouncy Castle FIPS Provider Custom Nonce/IV"));
                }
                return new MySecureRandomSpi(random);
            }
        });
    }

    private byte[] generatePersonalizationString()
    {
        return Arrays.concatenate(Strings.toByteArray("NonceAndIV"),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }

    private class MySecureRandomSpi
        extends SecureRandomSpi
    {
        private final FipsSecureRandom baseRandom;
        private final SecureRandomParameters params;

        protected MySecureRandomSpi(FipsSecureRandom baseRandom)
        {
            this.baseRandom = baseRandom;
            this.params = DrbgParameters.instantiation(
                baseRandom.getSecurityStrength(),
                baseRandom.isPredictionResistant() ? DrbgParameters.Capability.PR_AND_RESEED : DrbgParameters.Capability.RESEED_ONLY,
                baseRandom.getPersonalizationString());
        }

        @Override
        protected void engineSetSeed(byte[] bytes)
        {
            baseRandom.setSeed(bytes);
        }

        @Override
        protected void engineNextBytes(byte[] bytes, SecureRandomParameters params)
        {
            if (params instanceof DrbgParameters.NextBytes)
            {
                DrbgParameters.NextBytes p = (DrbgParameters.NextBytes)params;
                if (p.getStrength() > baseRandom.getSecurityStrength())
                {
                    throw new IllegalArgumentException("maximum strength of DRBG is " + baseRandom.getSecurityStrength() + " bits");
                }
                if (p.getPredictionResistance() && !baseRandom.isPredictionResistant())
                {
                    throw new IllegalArgumentException("prediction resistance not available");
                }

                baseRandom.nextBytes(bytes, p.getAdditionalInput());
            }
            else
            {
                throw new IllegalArgumentException("unrecognized DrbgParameters: " + params.getClass());
            }
        }

        @Override
        protected void engineNextBytes(byte[] bytes)
        {
            baseRandom.nextBytes(bytes);
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes)
        {
            return baseRandom.generateSeed(numBytes);
        }

        @Override
        protected void engineReseed(SecureRandomParameters params)
        {
            if (params instanceof DrbgParameters.Reseed)
            {
                DrbgParameters.Reseed p = (DrbgParameters.Reseed)params;

                if (p.getPredictionResistance() && !baseRandom.isPredictionResistant())
                {
                    throw new IllegalArgumentException("prediction resistance not available");
                }

                baseRandom.reseed(p.getAdditionalInput());
            }
            else
            {
                if (params != null)
                {
                    throw new IllegalArgumentException("unrecognized DrbgParameters: " + params.getClass());
                }

                baseRandom.reseed();
            }
        }

        @Override
        protected SecureRandomParameters engineGetParameters()
        {
            return params;
        }
    }
}
