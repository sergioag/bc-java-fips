package org.bouncycastle.jcajce.provider;


import java.security.DrbgParameters;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.SecureRandomSpi;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.SecureRandomProvider;
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
        provider.setProperty("SecureRandom.DEFAULT ThreadSafe", "true");
        provider.addAlgorithmImplementation("SecureRandom.DEFAULT", PREFIX + "DefSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final PooledSecureRandomProvider pooledProv = new PooledSecureRandomProvider(provider, constructorParameter);

                return new MySecureRandomSpi(pooledProv);
            }
        });

        provider.setProperty("SecureRandom.NONCEANDIV ThreadSafe", "true");
        provider.addAlgorithmImplementation("SecureRandom.NONCEANDIV", PREFIX + "NonceAndIVSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final PooledNonceSecureRandomProvider pooledProv = new PooledNonceSecureRandomProvider(provider, constructorParameter);

                return new MySecureRandomSpi(pooledProv);
            }
        });
    }

    private byte[] generatePersonalizationString()
    {
        return Arrays.concatenate(Strings.toByteArray("NonceAndIV"),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
    
    private class PooledSecureRandomProvider
        implements SecureRandomProvider
    {
        private final AtomicReference<SecureRandom>[] providerDefaultRandom = new AtomicReference[BouncyCastleFipsProvider.POOL_SIZE];
        private final BouncyCastleFipsProvider provider;
        private final Object constructorParameter;

        PooledSecureRandomProvider(BouncyCastleFipsProvider provider, Object constructorParameter)
        {
            this.provider = provider;
            this.constructorParameter = constructorParameter;
            for (int i = 0; i != providerDefaultRandom.length; i++)
            {
                providerDefaultRandom[i] = new AtomicReference<SecureRandom>();
            }
        }

        public SecureRandom get()
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            int rngIndex = (Thread.currentThread().hashCode() & (BouncyCastleFipsProvider.POOL_SIZE - 1)) % providerDefaultRandom.length;
            if (providerDefaultRandom[rngIndex].get() == null)
            {
                synchronized (providerDefaultRandom)
                {
                    if (providerDefaultRandom[rngIndex].get() == null)
                    {
                        final SecureRandom random;
                        if (constructorParameter == null)
                        {
                            random = provider.getDefaultSecureRandom();
                        }
                        else
                        {
                            DrbgParameters.Instantiation params = (DrbgParameters.Instantiation)constructorParameter;
                            final EntropySourceProvider entropySourceProvider = provider.getEntropySourceProvider();
                            final EntropySource seedSource = entropySourceProvider.get((params.getStrength() / 2) + 1);

                            random = provider.getProviderDefaultRandomBuilder()
                                                .fromEntropySource(entropySourceProvider)
                                                .setSecurityStrength(params.getStrength())
                                                .setPersonalizationString(params.getPersonalizationString())
                                                .build(seedSource.getEntropy(),
                                                    params.getCapability() == DrbgParameters.Capability.PR_AND_RESEED, Strings.toByteArray("Bouncy Castle FIPS Custom Default"));
                        }

                        providerDefaultRandom[rngIndex].compareAndSet(null, random);
                    }
                }
            }

            return providerDefaultRandom[rngIndex].get();
        }
    }

    private class PooledNonceSecureRandomProvider
        implements SecureRandomProvider
    {
        private final AtomicReference<SecureRandom>[] providerDefaultRandom = new AtomicReference[BouncyCastleFipsProvider.POOL_SIZE];
        private final BouncyCastleFipsProvider provider;
        private final Object constructorParameter;

        PooledNonceSecureRandomProvider(BouncyCastleFipsProvider provider, Object constructorParameter)
        {
            this.provider = provider;
            this.constructorParameter = constructorParameter;
            for (int i = 0; i != providerDefaultRandom.length; i++)
            {
                providerDefaultRandom[i] = new AtomicReference<SecureRandom>();
            }
        }

        public SecureRandom get()
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            int rngIndex = (Thread.currentThread().hashCode() & (BouncyCastleFipsProvider.POOL_SIZE - 1)) % providerDefaultRandom.length;
            if (providerDefaultRandom[rngIndex].get() == null)
            {
                synchronized (providerDefaultRandom)
                {
                    if (providerDefaultRandom[rngIndex].get() == null)
                    {
                        final EntropySourceProvider entropySourceProvider = provider.getEntropySourceProvider();
                        final EntropySource seedSource = entropySourceProvider.get((provider.getProviderDefaultSecurityStrength() / 2) + 1);
                        final FipsSecureRandom random;

                        if (constructorParameter == null)
                        {
                            random = provider.getProviderDefaultRandomBuilder()
                                .fromEntropySource(entropySourceProvider)
                                .setPersonalizationString(generatePersonalizationString())
                                .build(seedSource.getEntropy(), false, Strings.toByteArray("Bouncy Castle FIPS Provider Nonce/IV"));
                        }
                        else
                        {
                            DrbgParameters.Instantiation params = (DrbgParameters.Instantiation)constructorParameter;

                            random = provider.getProviderDefaultRandomBuilder()
                                .fromEntropySource(entropySourceProvider)
                                .setSecurityStrength(params.getStrength())
                                .setPersonalizationString(params.getPersonalizationString())
                                .build(seedSource.getEntropy(),
                                    params.getCapability() == DrbgParameters.Capability.PR_AND_RESEED,
                                    Strings.toByteArray("Bouncy Castle FIPS Provider Custom Nonce/IV"));
                        }

                        providerDefaultRandom[rngIndex].compareAndSet(null, random);
                    }
                }
            }

            return providerDefaultRandom[rngIndex].get();
        }
    }

    private class MySecureRandomSpi
        extends SecureRandomSpi
    {
        private final SecureRandomParameters params;
        private final SecureRandomProvider provider;

        protected MySecureRandomSpi(SecureRandomProvider provider)
        {
            this.provider = provider;
            SecureRandom baseRandom = provider.get();
            if (baseRandom instanceof FipsSecureRandom)
            {
                FipsSecureRandom fipsRandom = (FipsSecureRandom)baseRandom;

                this.params = DrbgParameters.instantiation(
                    fipsRandom.getSecurityStrength(),
                    fipsRandom.isPredictionResistant() ? DrbgParameters.Capability.PR_AND_RESEED : DrbgParameters.Capability.RESEED_ONLY,
                    fipsRandom.getPersonalizationString());
            }
            else
            {
                this.params = null;
            }
        }

        @Override
        protected void engineSetSeed(byte[] bytes)
        {
            this.provider.get().setSeed(bytes);
        }

        @Override
        protected void engineNextBytes(byte[] bytes, SecureRandomParameters params)
        {
            if (params instanceof DrbgParameters.NextBytes)
            {
                FipsSecureRandom baseRandom = (FipsSecureRandom)provider.get();
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
                if (params == null)
                {
                    super.engineNextBytes(bytes, params);
                }
                throw new IllegalArgumentException("unrecognized DrbgParameters: " + params.getClass());
            }
        }

        @Override
        protected void engineNextBytes(byte[] bytes)
        {
            provider.get().nextBytes(bytes);
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes)
        {
            return provider.get().generateSeed(numBytes);
        }

        @Override
        protected void engineReseed(SecureRandomParameters params)
        {
            if (params instanceof DrbgParameters.Reseed)
            {
                DrbgParameters.Reseed p = (DrbgParameters.Reseed)params;
                FipsSecureRandom baseRandom = (FipsSecureRandom)provider.get();

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

                SecureRandom baseRandom = provider.get();
                if (baseRandom instanceof FipsSecureRandom)
                {
                    baseRandom.reseed();
                }
                else
                {
                    super.engineReseed(params);
                }
            }
        }

        @Override
        protected SecureRandomParameters engineGetParameters()
        {
            return params;
        }
    }
}
