package org.bouncycastle.jcajce.provider;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.Scrypt;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;

class ProvPBESCRYPT
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvPBESCRYPT.class.getName();

    public void configure(BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory.SCRYPT", PREFIX + "$ScryptWithUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseScrypt();
            }
        });
        provider.addAlias("SecretKeyFactory", "SCRYPT", "SCRYPTWITHUTF8");
        provider.addAlias("SecretKeyFactory", "SCRYPT", MiscObjectIdentifiers.id_scrypt);
    }

    static class BaseScrypt
        extends BaseKDFSecretKeyFactory
    {

        private Scrypt.KDFFactory sFact = new Scrypt.KDFFactory();

        public BaseScrypt()
        {
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof ScryptKeySpec)
            {
                ScryptKeySpec pbeSpec = (ScryptKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("Salt S must be provided.");
                }

                if (pbeSpec.getCostParameter() <= 1)
                {
                    throw new InvalidKeySpecException("Cost parameter N must be > 1.");
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                Scrypt.Parameters p = Scrypt.ALGORITHM.using(pbeSpec.getSalt(), pbeSpec.getCostParameter(), pbeSpec.getBlockSize(),
                    pbeSpec.getParallelizationParameter(), PasswordConverter.UTF8, pbeSpec.getPassword());
                byte[] keyBytes = new byte[(pbeSpec.getKeyLength() + 7) / 8];

                try
                {
                    sFact.createKDFCalculator(p).generateBytes(keyBytes);
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }

                return new SecretKeySpec(keyBytes, "SCRYPT");
            }
            if (keySpec == null)
            {
                throw new InvalidKeySpecException("KeySpec cannot be null");
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec.getClass().getName());
        }
    }
}
