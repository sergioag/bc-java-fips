package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsSHS;

final class ProvKMAC
    extends AlgorithmProvider
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvKMAC.class.getName();

    @Override
    void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyGenerator.KMACWITHSHAKE128", PREFIX + "$KeyGenerator128", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "KMACWITHSHAKE128", 256, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        // keySize ignored
                        return new FipsSHS.KeyGenerator(FipsSHS.KMAC128.getAlgorithm(), keySize, random);
                    }
                });
            }
        });
        provider.addAlias("KeyGenerator", "KMACWITHSHAKE128", NISTObjectIdentifiers.id_KmacWithSHAKE128);
        provider.addAlias("KeyGenerator", "KMACWITHSHAKE128", "KMAC128");

        provider.addAlgorithmImplementation("Mac.KMACWITHSHAKE128", PREFIX + "KMACwithSHAKE128", generalAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsSHS.KMAC128, new FipsSHS.MACOperatorFactory(), new KMACParametersCreator(FipsSHS.KMAC128));
            }
        });
        provider.addAlias("Mac", "KMACWITHSHAKE128", NISTObjectIdentifiers.id_KmacWithSHAKE128);
        provider.addAlias("Mac", "KMACWITHSHAKE128", "KMAC128");

        provider.addAlgorithmImplementation("KeyGenerator.KMACWITHSHAKE256", PREFIX + "$KeyGenerator256", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "KMACWITHSHAKE256", 512, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        // keySize ignored
                        return new FipsSHS.KeyGenerator(FipsSHS.KMAC256.getAlgorithm(), keySize, random);
                    }
                });
            }
        });
        provider.addAlias("KeyGenerator", "KMACWITHSHAKE256", NISTObjectIdentifiers.id_KmacWithSHAKE256);
        provider.addAlias("KeyGenerator", "KMACWITHSHAKE256", "KMAC256");

        provider.addAlgorithmImplementation("Mac.KMACWITHSHAKE256", PREFIX + "KMACwithSHAKE256", generalAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsSHS.KMAC256, new FipsSHS.MACOperatorFactory(), new KMACParametersCreator(FipsSHS.KMAC256));
            }
        });
        provider.addAlias("Mac", "KMACWITHSHAKE256", NISTObjectIdentifiers.id_KmacWithSHAKE256);
        provider.addAlias("Mac", "KMACWITHSHAKE256", "KMAC256");
    }
}
