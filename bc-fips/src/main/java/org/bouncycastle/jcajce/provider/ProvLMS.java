package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SignatureOperatorFactory;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.crypto.general.LMS;
import org.bouncycastle.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec;

final class ProvLMS
    extends AsymmetricAlgorithmProvider
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "org.bouncycastle.interfaces.LMSKey");
        generalAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".lms.";

    private static final PublicKeyConverter<AsymmetricLMSPublicKey> lmsPublicKeyConverter = new PublicKeyConverter<AsymmetricLMSPublicKey>()
    {
        public AsymmetricLMSPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvLMSPublicKey)
            {
                return ((ProvLMSPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricLMSPublicKey(Utils.getKeyEncoding(key));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify LMS public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricLMSPrivateKey> lmsPrivateKeyConverter = new PrivateKeyConverter<AsymmetricLMSPrivateKey>()
    {
        public AsymmetricLMSPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvLMSPrivateKey)
            {
                return ((ProvLMSPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricLMSPrivateKey(PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify LMS private key: " + e.getMessage(), e);
                }
            }
        }
    };

    static class KeyFactorySpi
        extends BaseKeyFactory
    {
        String algorithm;

        public KeyFactorySpi(
            String algorithm)
        {
            this.algorithm = algorithm;
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvLMSPublicKey(lmsPublicKeyConverter.convertKey(LMS.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvLMSPrivateKey(lmsPrivateKeyConverter.convertKey(LMS.ALGORITHM, (PrivateKey)key));
            }
            else if (key != null)
            {
                throw new InvalidKeyException("Key type unrecognized: " + key.getClass().getName());
            }
            throw new InvalidKeyException("Key is null");
        }

        protected KeySpec engineGetKeySpec(
            Key key,
            Class spec)
            throws InvalidKeySpecException
        {
            if (spec == null)
            {
                throw new InvalidKeySpecException("null spec is invalid");
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

            if (algOid.equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig))
            {
                return new ProvLMSPrivateKey(keyInfo);
            }

            throw new IOException("algorithm identifier " + algOid + " in key not recognized");
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

            if (algOid.equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig))
            {
                return new ProvLMSPublicKey(keyInfo);
            }

            throw new IOException("algorithm identifier " + algOid + " in key not recognized");
        }
    }

    static class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider provider;

        LMS.KeyGenParameters param;
        LMS.KeyPairGenerator engine;

        SecureRandom random;
        boolean initialised = false;

        public KeyPairGeneratorSpi(BouncyCastleFipsProvider provider)
        {
            super("LMS");
            this.provider = provider;
        }

        public void initialize(
            int strength)
        {
            initialize(strength, provider.getDefaultSecureRandom());
        }

        public void initialize(
            int strength,
            SecureRandom random)
        {
            throw new UnsupportedOperationException("use AlgorithmParameterSpec");
        }

        public void initialize(
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            initialize(params, provider.getDefaultSecureRandom());
        }

        public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (params instanceof LMSKeyGenParameterSpec)
            {
                LMSKeyGenParameterSpec lmsParams = (LMSKeyGenParameterSpec)params;

                param = new LMS.KeyGenParameters(lmsParams.getKeyParams());

                engine = new LMS.KeyPairGenerator(param, random);
            }
            else if (params instanceof LMSHSSKeyGenParameterSpec)
            {
                LMSKeyGenParameterSpec[] lmsParams = ((LMSHSSKeyGenParameterSpec)params).getLMSSpecs();
                LMS.KeyParameters[] hssParams = new LMS.KeyParameters[lmsParams.length];
                for (int i = 0; i != lmsParams.length; i++)
                {
                    hssParams[i] = lmsParams[i].getKeyParams();
                }
                param = new LMS.KeyGenParameters(hssParams);

                engine = new LMS.KeyPairGenerator(param, random);
            }
            else
            {
                if (params == null)
                {
                    throw new InvalidAlgorithmParameterException("parameterSpec cannot be null");
                }
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }

            initialised = true;
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                param = new LMS.KeyGenParameters(LMS.lms_sha256_n32_h10.using(LMS.sha256_n32_w4));

                if (random == null)
                {
                    random = provider.getDefaultSecureRandom();
                }

                engine = new LMS.KeyPairGenerator(param, random);
                initialised = true;
            }

            AsymmetricKeyPair<AsymmetricLMSPublicKey, AsymmetricLMSPrivateKey> pair = engine.generateKeyPair();

            return new KeyPair(new ProvLMSPublicKey(pair.getPublicKey()), new ProvLMSPrivateKey(pair.getPrivateKey()));
        }
    }

    static class LMSSignatureSpi
        extends SignatureSpi
        implements PKCSObjectIdentifiers, X509ObjectIdentifiers
    {
        private static final byte TRAILER_IMPLICIT = (byte)0xBC;

        private final SignatureOperatorFactory operatorFactory;
        private final PublicKeyConverter publicKeyConverter;
        private final PrivateKeyConverter privateKeyConverter;
        private final BouncyCastleFipsProvider fipsProvider;
        private final AlgorithmParameterSpec originalSpec;

        protected Parameters parameters;
        protected OutputVerifier verifier;
        protected OutputSigner signer;
        protected UpdateOutputStream dataStream;

        protected AlgorithmParameters engineParams;
        protected AlgorithmParameterSpec paramSpec;

        protected AsymmetricKey key;
        protected boolean isInitState = true;

        protected LMSSignatureSpi(
            BouncyCastleFipsProvider fipsProvider,
            SignatureOperatorFactory operatorFactory,
            PublicKeyConverter publicKeyConverter,
            PrivateKeyConverter privateKeyConverter,
            Parameters parameters)
        {
            this.fipsProvider = fipsProvider;
            this.operatorFactory = operatorFactory;
            this.publicKeyConverter = publicKeyConverter;
            this.privateKeyConverter = privateKeyConverter;
            this.parameters = parameters;
            this.originalSpec = null;
        }

        protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
        {
            key = publicKeyConverter.convertKey(parameters.getAlgorithm(), publicKey);
            initVerify();
            isInitState = true;
        }

        protected void engineInitSign(
            PrivateKey privateKey)
            throws InvalidKeyException
        {
            key = privateKeyConverter.convertKey(parameters.getAlgorithm(), privateKey);
            if (((AsymmetricLMSPrivateKey)key).getUsagesRemaining() == 0)
            {
                throw new InvalidKeyException("private key exhausted");
            }
            this.appRandom = fipsProvider.getDefaultSecureRandom();
            isInitState = true;
        }

        protected void engineInitSign(
            PrivateKey privateKey,
            SecureRandom random)
            throws InvalidKeyException
        {
            key = privateKeyConverter.convertKey(parameters.getAlgorithm(), privateKey);
            this.appRandom = (random != null) ? random : fipsProvider.getDefaultSecureRandom();
            isInitState = true;
        }

        protected void engineUpdate(
            byte b)
            throws SignatureException
        {
            if (isInitState && key instanceof AsymmetricLMSPrivateKey)
            {
                initSign();
            }
            isInitState = false;
            dataStream.update(b);
        }

        protected void engineUpdate(
            byte[] b,
            int off,
            int len)
            throws SignatureException
        {
            if (isInitState && key instanceof AsymmetricLMSPrivateKey)
            {
                initSign();
            }
            isInitState = false;
            dataStream.update(b, off, len);
        }

        protected byte[] engineSign()
            throws SignatureException
        {
            if (isInitState && key instanceof AsymmetricLMSPrivateKey)
            {
                initSign();
            }
            
            try
            {
                isInitState = true;
                return signer.getSignature();
            }
            catch (Exception e)
            {
                throw new SignatureException(e.toString(), e);
            }
        }

        protected boolean engineVerify(
            byte[] sigBytes)
            throws SignatureException
        {
            try
            {
                isInitState = true;
                return verifier.isVerified(sigBytes);
            }
            catch (Exception e)
            {
                throw new SignatureException(e.toString(), e);
            }
        }

        protected void engineSetParameter(
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("no ParameterSpec supported");
        }

        private void initVerify()
        {
            verifier = operatorFactory.createVerifier((AsymmetricPublicKey)key, parameters);
            dataStream = verifier.getVerifyingStream();
        }

        private void initSign()
            throws SignatureException
        {
            try
            {
                // TODO: should change addRandomIfNeeded in 1.1 (maybe? - it's correct in this case but is it always?
                signer = Utils.addRandomIfNeeded(operatorFactory.createSigner((AsymmetricPrivateKey)key, parameters), appRandom);
                dataStream = signer.getSigningStream();
            }
            catch (Exception e)
            {
                throw new SignatureException(e.getMessage(), e);
            }
        }

        protected AlgorithmParameters engineGetParameters()
        {
            return engineParams;
        }

        /**
         * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
         */
        protected void engineSetParameter(
            String param,
            Object value)
        {
            throw new UnsupportedOperationException("SetParameter unsupported");
        }

        /**
         * @deprecated replaced with <a href = "#engineGetParameters()">engineGetParameters()</a>
         */
        protected Object engineGetParameter(
            String param)
        {
            throw new UnsupportedOperationException("GetParameter unsupported");
        }
    }

    @Override
    void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyFactory.LMS", PREFIX + "KeyFactorySpi$LMS", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi("LMS");
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.LMS", PREFIX + "KeyPairGenerator", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider);
            }
        }));

        provider.addAlgorithmImplementation("Signature.LMS", PREFIX + "Signature$LMS", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new LMSSignatureSpi(provider, new LMS.OperatorFactory(), lmsPublicKeyConverter, lmsPrivateKeyConverter, LMS.SIG);
            }
        }));
        provider.addAlias("Signature", "LMS", PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
        
        registerOid(provider, PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS", new KeyFactorySpi("LMS"));
    }
}
