package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;

import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.Poly1305;

final class ProvPoly1305
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvPoly1305.class.getName();

    @Override
    void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyGenerator.POLY1305", PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "POLY1305", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        // keySize ignored
                        return new Poly1305.KeyGenerator(random);
                    }
                });
            }
        }));
        addKeyGenAlias(provider, "AES");
        addKeyGenAlias(provider, "CAMELLIA");
        addKeyGenAlias(provider, "SEED");
        addKeyGenAlias(provider, "SERPENT");
        addKeyGenAlias(provider, "TWOFISH");

        provider.addAlgorithmImplementation("Mac.POLY1305", PREFIX + "POLY1305", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Poly1305.MAC, new Poly1305.MACOperatorFactory(), new AuthParametersCreator(Poly1305.MAC));
            }
        }));
        provider.addAlgorithmImplementation("Mac.POLY1305-AES", PREFIX + "POLY1305-AES", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Poly1305.MACwithAES, new Poly1305.MACOperatorFactory(), new AuthParametersCreator(Poly1305.MACwithAES));
            }
        }));
        provider.addAlias("Mac", "POLY1305-AES", "POLY1305AES");

        provider.addAlgorithmImplementation("Mac.POLY1305-CAMELLIA", PREFIX + "POLY1305-CAMELLIA", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Poly1305.MACwithCAMELLIA, new Poly1305.MACOperatorFactory(), new AuthParametersCreator(Poly1305.MACwithCAMELLIA));
            }
        }));
        provider.addAlias("Mac", "POLY1305-CAMELLIA", "POLY1305CAMELLIA");

        provider.addAlgorithmImplementation("Mac.POLY1305-SEED", PREFIX + "POLY1305-SEED", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Poly1305.MACwithSEED, new Poly1305.MACOperatorFactory(), new AuthParametersCreator(Poly1305.MACwithSEED));
            }
        }));
        provider.addAlias("Mac", "POLY1305-SEED", "POLY1305SEED");

        provider.addAlgorithmImplementation("Mac.POLY1305-SERPENT", PREFIX + "POLY1305-SERPENT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Poly1305.MACwithSerpent, new Poly1305.MACOperatorFactory(), new AuthParametersCreator(Poly1305.MACwithSerpent));
            }
        }));
        provider.addAlias("Mac", "POLY1305-SERPENT", "POLY1305SERPENT");

        provider.addAlgorithmImplementation("Mac.POLY1305-TWOFISH", PREFIX + "POLY1305-TWOFISH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Poly1305.MACwithTwofish, new Poly1305.MACOperatorFactory(), new AuthParametersCreator(Poly1305.MACwithTwofish));
            }
        }));
        provider.addAlias("Mac", "POLY1305-TWOFISH", "POLY1305TWOFISH");
    }

    private static void addKeyGenAlias(BouncyCastleFipsProvider provider, String alg)
    {
        provider.addAlias("KeyGenerator", "POLY1305", "POLY1305-" + alg, "POLY1305" + alg);
    }
}
