package org.bouncycastle.jcajce.provider;


import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.SecureRandomProvider;
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
                return new SecureRandomSpi()
                {
                    @Override
                    protected void engineSetSeed(byte[] bytes)
                    {
                        final SecureRandom random = provider.getDefaultSecureRandom();

                        random.setSeed(bytes);
                    }

                    @Override
                    protected void engineNextBytes(byte[] bytes)
                    {
                        final SecureRandom random = provider.getDefaultSecureRandom();

                        random.nextBytes(bytes);
                    }

                    @Override
                    protected byte[] engineGenerateSeed(int numBytes)
                    {
                        final SecureRandom random = provider.getDefaultSecureRandom();

                        return random.generateSeed(numBytes);
                    }
                };
            }
        });

        final PooledNonceSecureRandomProvider nonceDRBGProv = new PooledNonceSecureRandomProvider(provider);

        provider.setProperty("SecureRandom.NONCEANDIV ThreadSafe", "true");
        provider.addAlgorithmImplementation("SecureRandom.NONCEANDIV", PREFIX + "NonceAndIVSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new SecureRandomSpi()
                {
                    @Override
                    protected void engineSetSeed(byte[] bytes)
                    {
                        SecureRandom random = nonceDRBGProv.get();

                        random.setSeed(bytes);
                    }

                    @Override
                    protected void engineNextBytes(byte[] bytes)
                    {
                        SecureRandom random = nonceDRBGProv.get();

                        random.nextBytes(bytes);
                    }

                    @Override
                    protected byte[] engineGenerateSeed(int numBytes)
                    {
                        SecureRandom random = nonceDRBGProv.get();

                        return random.generateSeed(numBytes);
                    }
                };
            }
        });
    }

    private class PooledNonceSecureRandomProvider
        implements SecureRandomProvider
    {
        private final AtomicReference<SecureRandom>[] providerDefaultRandom = new AtomicReference[BouncyCastleFipsProvider.POOL_SIZE];
        private final BouncyCastleFipsProvider provider;

        PooledNonceSecureRandomProvider(final BouncyCastleFipsProvider provider)
        {
            this.provider = provider;
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
                        EntropySourceProvider entropySourceProvider = provider.getEntropySourceProvider();
                        EntropySource seedSource = entropySourceProvider.get((provider.getProviderDefaultSecurityStrength() / 2) + 1);
                        providerDefaultRandom[rngIndex].compareAndSet(null, provider.getProviderDefaultRandomBuilder()
                            .fromEntropySource(entropySourceProvider)
                            .setPersonalizationString(generatePersonalizationString())
                            .build(seedSource.getEntropy(), false, Strings.toByteArray("Bouncy Castle FIPS Provider Nonce/IV")));
                    }
                }
            }

            return providerDefaultRandom[rngIndex].get();
        }
    }

    private byte[] generatePersonalizationString()
    {
        return Arrays.concatenate(Strings.toByteArray("NonceAndIV"),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
}
