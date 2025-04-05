package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.AccessController;
import java.security.PrivilegedAction;

import org.bouncycastle.tls.crypto.impl.AEADNonceGenerator;
import org.bouncycastle.tls.crypto.impl.AEADNonceGeneratorFactory;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;

class GCMFipsUtil
{
    static AEADNonceGeneratorFactory getDefaultFipsGCMNonceGeneratorFactory()
    {
        return getBcFipsNonceGeneratorFactory();
    }

    private static final Class fipsNonceGeneratorClass = lookup("org.bouncycastle.crypto.fips.FipsNonceGenerator");

    private static AEADNonceGeneratorFactory getBcFipsNonceGeneratorFactory()
    {
        if (fipsNonceGeneratorClass != null)
        {
            return new AEADNonceGeneratorFactory()
            {

                @Override
                public AEADNonceGenerator create(byte[] baseNonce, int counterSizeInBits)
                {
                    return new BCFipsAEADNonceGenerator(baseNonce, counterSizeInBits);
                }
            };
        }

        return null;
    }

    static Class lookup(final String className)
    {
        if (null == className)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>()
        {
            public Class<?> run()
            {
                try
                {
                    ClassLoader classLoader = TlsAEADCipher.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ? Class.forName(className)
                        : classLoader.loadClass(className);
                    return clazz;
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }
}
