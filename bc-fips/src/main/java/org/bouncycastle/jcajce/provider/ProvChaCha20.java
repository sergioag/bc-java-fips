package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.ChaCha20;

final class ProvChaCha20
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvChaCha20.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            return new ChaCha20ParametersCreator((ChaCha20.Parameters)parameters);
        }
    };

    private ParametersCreatorProvider<Parameters> nonceParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            return new IvParametersCreator((ChaCha20.AuthParameters)parameters);
        }
    };

    class ChaCha20ParametersCreator<T extends ChaCha20.Parameters>
        implements ParametersCreator
    {
        private final ChaCha20.Parameters baseParameters;

        ChaCha20ParametersCreator(ChaCha20.Parameters baseParameters)
        {
            this.baseParameters = baseParameters;
        }

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (spec instanceof IvParameterSpec)
            {
                return baseParameters.withIV(((IvParameterSpec)spec).getIV()).withCounter(0);
            }

            if (ChaCha20SpecUtil.isChaCha20Spec(spec))
            {
                try
                {
                    ASN1Sequence s = ChaCha20SpecUtil.extractChaCha20Parameters(spec);
                    return baseParameters
                        .withIV(ASN1OctetString.getInstance(s.getObjectAt(0)).getOctets())
                        .withCounter(ASN1Integer.getInstance(s.getObjectAt(1)).intValueExact());
                }
                catch (Exception e)
                {
                    throw new InvalidAlgorithmParameterException("Cannot process ChaCha20ParameterSpec: " + e.getMessage(), e);
                }
            }

            if (forEncryption && baseParameters.getAlgorithm().requiresAlgorithmParameters())
            {
                return baseParameters.withIV(random).withCounter(0);
            }

            return baseParameters;
        }
    }

    @Override
    void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyGenerator.CHACHA20", PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "ChaCha20", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        // keySize ignored
                        return new ChaCha20.KeyGenerator(random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "CHACHA20", "CHACHA7539", "CHACHA20-POLY1305");
        provider.addAlias("KeyGenerator", "CHACHA20", PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305);

        provider.addAlgorithmImplementation("AlgorithmParameters.CHACHA20", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("ChaCha20");
            }
        }));
        provider.addAlias("AlgorithmParameters", "CHACHA20", "CHACHA7539");

        provider.addAlgorithmImplementation("AlgorithmParameters.CHACHA20-POLY1305", PREFIX + "$AlgParamsCP", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("ChaCha20-Poly1305");
            }
        }));
        provider.addAlias("AlgorithmParameters", "CHACHA20-POLY1305", PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.CHACHA20",PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "ChaCha20", 12);
            }
        }));
        provider.addAlias("AlgorithmParameterGenerator", "CHACHA20", "CHACHA7539");

        provider.addAlgorithmImplementation("Cipher.CHACHA20", PREFIX + "$Base", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 96, ChaCha20.STREAM)
                    .withParameters(ChaCha20SpecUtil.getCipherSpecClasses())
                    .withGeneralOperators(generalParametersCreatorProvider, new ChaCha20.OperatorFactory(), null).build();
            }
        }));
        provider.addAlias("Cipher", "CHACHA20", "CHACHA7539");

        provider.addAlgorithmImplementation("Cipher.CHACHA20-POLY1305", PREFIX + "$ChaPolyBase", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 96, ChaCha20.WithPoly1305)
                    .withParameters(ChaCha20SpecUtil.getCipherSpecClasses())
                    .withGeneralOperators(nonceParametersCreatorProvider, null, new ChaCha20.AEADOperatorFactory()).build();
            }
        }));
        provider.addAlias("Cipher", "CHACHA20-POLY1305", PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305);
    }
}
