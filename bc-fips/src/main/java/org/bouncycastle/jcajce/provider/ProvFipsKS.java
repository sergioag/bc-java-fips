package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.util.io.Streams;

class ProvFipsKS
    extends AlgorithmProvider
{
    private static class FIPSKeyStore
        extends KeyStoreSpi
    {
        private final boolean isImmutable;
        private final BouncyCastleFipsProvider provider;

        private KeyStoreSpi keyStore;

        public FIPSKeyStore(boolean isImmutable, BouncyCastleFipsProvider provider)
        {
            this.isImmutable = isImmutable;
            this.provider = provider;
        }

        public Enumeration engineAliases()
        {
            return keyStore.engineAliases();
        }

        public boolean engineContainsAlias(
            String alias)
        {
            return keyStore.engineContainsAlias(alias);
        }

        public void engineDeleteEntry(
            String alias)
            throws KeyStoreException
        {
            if (isImmutable)
            {
                throw new KeyStoreException("delete operation not supported in immutable mode");
            }
            keyStore.engineDeleteEntry(alias);
        }

        public Certificate engineGetCertificate(
            String alias)
        {
            return keyStore.engineGetCertificate(alias);
        }

        public String engineGetCertificateAlias(
            Certificate cert)
        {
            return keyStore.engineGetCertificateAlias(cert);
        }

        public Certificate[] engineGetCertificateChain(
            String alias)
        {
            return keyStore.engineGetCertificateChain(alias);
        }

        public Date engineGetCreationDate(String alias)
        {
            return keyStore.engineGetCreationDate(alias);
        }

        public Key engineGetKey(
            String alias,
            char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException
        {
            return keyStore.engineGetKey(alias, password);
        }

        public boolean engineIsCertificateEntry(
            String alias)
        {
            return keyStore.engineIsCertificateEntry(alias);
        }

        public boolean engineIsKeyEntry(
            String alias)
        {
            return keyStore.engineIsKeyEntry(alias);
        }

        public void engineSetCertificateEntry(
            String alias,
            Certificate cert)
            throws KeyStoreException
        {
            if (isImmutable)
            {
                throw new KeyStoreException("set operation not supported in immutable mode");
            }
            keyStore.engineSetCertificateEntry(alias, cert);
        }

        public void engineSetKeyEntry(
            String alias,
            byte[] key,
            Certificate[] chain)
            throws KeyStoreException
        {
            if (isImmutable)
            {
                throw new KeyStoreException("set operation not supported in immutable mode");
            }
            keyStore.engineSetKeyEntry(alias, key, chain);
        }

        public void engineSetKeyEntry(
            String alias,
            Key key,
            char[] password,
            Certificate[] chain)
            throws KeyStoreException
        {
            if (isImmutable)
            {
                throw new KeyStoreException("set operation not supported in immutable mode");
            }
            keyStore.engineSetKeyEntry(alias, key, password, chain);
        }

        public int engineSize()
        {
            return keyStore.engineSize();
        }

        public void engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)
            throws KeyStoreException
        {
            if (isImmutable)
            {
                throw new KeyStoreException("set operation not supported in immutable mode");
            }
            keyStore.engineSetEntry(alias, entry, protParam);
        }

        public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter)
            throws IOException, NoSuchAlgorithmException, CertificateException
        {
            if (keyStore != null)
            {
                if (isImmutable)
                {
                    throw new IOException("immutable keystore already loaded");
                }
            }

            if (loadStoreParameter == null)
            {
                engineLoad(null, null);
            }
            else if (loadStoreParameter instanceof BCLoadStoreParameter)
            {
                BCLoadStoreParameter bcParam = (BCLoadStoreParameter)loadStoreParameter;

                engineLoad(bcParam.getInputStream(), Utils.extractPassword(loadStoreParameter));
            }
            else
            {
                throw new IllegalArgumentException(
                    "no support for 'param' of type " + loadStoreParameter.getClass().getName());
            }
        }

        public void engineLoad(
            InputStream stream,
            char[] password)
            throws IOException, CertificateException, NoSuchAlgorithmException
        {
            if (keyStore != null)
            {
                if (isImmutable)
                {
                    throw new IOException("immutable keystore already loaded");
                }
            }

            if (stream == null)
            {
                if (isImmutable) // who knows why, but still...
                {
                    this.keyStore = new ProvBCFKS.BCFIPSImmutableKeyStoreSpi(provider);

                    keyStore.engineLoad(null, password);
                }
                else
                {
                    this.keyStore = new ProvBCFKS.BCFIPSKeyStoreSpi(false, provider);

                    keyStore.engineLoad(null, password);
                }

                return;
            }

            byte[] ksData = Streams.readAll(stream);

            if (isImmutable)
            {
                try
                {
                    this.keyStore = new ProvBCFKS.BCFIPSImmutableKeyStoreSpi(provider);

                    keyStore.engineLoad(new ByteArrayInputStream(ksData), password);
                }
                catch (Exception e)
                {
                    this.keyStore = new ProvJKS.JKSKeyStoreSpi(false, provider);

                    keyStore.engineLoad(new ByteArrayInputStream(ksData), password);
                }
            }
            else
            {
                try
                {
                    this.keyStore = new ProvBCFKS.BCFIPSKeyStoreSpi(false, provider);

                    keyStore.engineLoad(new ByteArrayInputStream(ksData), password);
                }
                catch (Exception e)
                {
                    this.keyStore = new ProvJKS.JKSKeyStoreSpi(false, provider);

                    keyStore.engineLoad(new ByteArrayInputStream(ksData), password);
                }
            }
        }

        public void engineStore(KeyStore.LoadStoreParameter param)
            throws IOException,
            NoSuchAlgorithmException, CertificateException
        {
            keyStore.engineStore(param);
        }

        public void engineStore(OutputStream stream, char[] password)
            throws IOException, CertificateException, NoSuchAlgorithmException
        {
            keyStore.engineStore(stream, password);
        }
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".FipsKS.";

    @Override
    void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyStore.FIPS", PREFIX + "FIPSKeyStore", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new FIPSKeyStore(false, provider);
            }
        });
        provider.addAlgorithmImplementation("KeyStore.IFIPS", PREFIX + "IFIPSKeyStore", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new FIPSKeyStore(true, provider);
            }
        });
        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("KeyStore.FIPS-DEF", PREFIX + "FIPSDefKeyStore", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new FIPSKeyStore(false, null);
                }
            }));
            provider.addAlgorithmImplementation("KeyStore.IFIPS-DEF", PREFIX + "IFIPDefSKeyStore", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new FIPSKeyStore(true,  null);
                }
            }));
        }
    }
}

