package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

class ProvPKIX
    extends AsymmetricAlgorithmProvider
{
    private static final Class revChkClass = ClassUtil.lookup("java.security.cert.PKIXRevocationChecker");

    public void configure(final BouncyCastleFipsProvider provider)
    {
        if (revChkClass != null)
        {
            provider.addAlgorithmImplementation("CertPathValidator.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new PKIXCertPathValidatorSpi_8(provider);
                }
            });
            provider.addAlgorithmImplementation("CertPathBuilder.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new PKIXCertPathBuilderSpi_8(provider);
                }
            });
        }
        else
        {
            provider.addAlgorithmImplementation("CertPathValidator.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new PKIXCertPathValidatorSpi(provider);
                }
            });
            provider.addAlgorithmImplementation("CertPathBuilder.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new PKIXCertPathBuilderSpi(provider);
                }
            });
        }
        provider.addAlgorithmImplementation("CertStore.COLLECTION", "org.bouncycastle.jce.provider.CertStoreCollectionSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                try
                {
                    return new CertStoreCollectionSpi((java.security.cert.CertStoreParameters)constructorParameter);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new NoSuchAlgorithmException("Unable to construct CertStore implementation: " + e.getMessage(), e);
                }
            }
        });
    }
}
