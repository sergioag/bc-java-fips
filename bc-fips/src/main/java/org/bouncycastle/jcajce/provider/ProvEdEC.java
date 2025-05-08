package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AgreementFactory;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPublicKey;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;

class ProvEdEC
    extends AsymmetricAlgorithmProvider
{
    private static final Map<String, String> generalEdDSAAttributes = new HashMap<String, String>();
    private static final Map<String, String> generalXDHAttributes = new HashMap<String, String>();

    private static final AgreementFactory xdhFactory = new EdEC.XDHAgreementFactory();

    static
    {
        generalEdDSAAttributes.put("SupportedKeyClasses", "org.bouncycastle.interfaces.EdDSAKey");
        generalEdDSAAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
        generalXDHAttributes.put("SupportedKeyClasses", "org.bouncycastle.interfaces.XDHKey");
        generalXDHAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".edec.";

    private static final byte x448_type = 0x6f;
    private static final byte x25519_type = 0x6e;
    private static final byte Ed448_type = 0x71;
    private static final byte Ed25519_type = 0x70;

    private static final PublicKeyConverter<AsymmetricEdDSAPublicKey> edPublicKeyConverter = new PublicKeyConverter<AsymmetricEdDSAPublicKey>()
    {
        public AsymmetricEdDSAPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvEdDSAPublicKey)
            {
                return ((ProvEdDSAPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricEdDSAPublicKey(Utils.getKeyEncoding(key));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify EdDSA public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricEdDSAPrivateKey> edPrivateKeyConverter = new PrivateKeyConverter<AsymmetricEdDSAPrivateKey>()
    {
        public AsymmetricEdDSAPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvEdDSAPrivateKey)
            {
                return ((ProvEdDSAPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricEdDSAPrivateKey(PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify EdDSA private key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PublicKeyConverter<AsymmetricXDHPublicKey> xPublicKeyConverter = new PublicKeyConverter<AsymmetricXDHPublicKey>()
    {
        public AsymmetricXDHPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvXDHPublicKey)
            {
                return ((ProvXDHPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricXDHPublicKey(Utils.getKeyEncoding(key));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify XDH public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricXDHPrivateKey> xPrivateKeyConverter = new PrivateKeyConverter<AsymmetricXDHPrivateKey>()
    {
        public AsymmetricXDHPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvXDHPrivateKey)
            {
                return ((ProvXDHPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricXDHPrivateKey(PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify XDH private key: " + e.getMessage(), e);
                }
            }
        }
    };

    static class KeyFactorySpi
        extends BaseKeyFactory
    {
        String algorithm;
        private final boolean isXdh;
        private final int specificBase;

        public KeyFactorySpi(
            String algorithm,
            boolean isXdh,
            int specificBase)
        {
            this.algorithm = algorithm;
            this.isXdh = isXdh;
            this.specificBase = specificBase;
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                if (isXdh)
                {
                    Algorithm alg = key.getAlgorithm().equals("X448") ? EdEC.Algorithm.X448 : EdEC.Algorithm.X25519;
                    return new ProvXDHPublicKey(xPublicKeyConverter.convertKey(alg, (PublicKey)key));
                }
                else
                {
                    Algorithm alg = key.getAlgorithm().equals("Ed448") ? FipsEdEC.Algorithm.Ed448 : FipsEdEC.Algorithm.Ed25519;
                    return new ProvEdDSAPublicKey(edPublicKeyConverter.convertKey(alg, (PublicKey)key));
                }
            }
            else if (key instanceof PrivateKey)
            {
                if (isXdh)
                {
                    Algorithm alg = key.getAlgorithm().equals("X448") ? EdEC.Algorithm.X448 : EdEC.Algorithm.X25519;
                    return new ProvXDHPrivateKey(xPrivateKeyConverter.convertKey(alg, (PrivateKey)key));
                }
                else
                {
                    Algorithm alg = key.getAlgorithm().equals("Ed448") ? FipsEdEC.Algorithm.Ed448 : FipsEdEC.Algorithm.Ed25519;
                    AsymmetricEdDSAPrivateKey privKey = edPrivateKeyConverter.convertKey(alg, (PrivateKey)key);
                    return new ProvEdDSAPrivateKey(privKey, new AsymmetricEdDSAPublicKey(alg, privKey.getPublicData()));
                }
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
            if (keySpec instanceof X509EncodedKeySpec)
            {
                byte[] enc = ((X509EncodedKeySpec)keySpec).getEncoded();

                // watch out for badly placed DER NULL - the default X509Cert will add these!
                if (enc[9] == 0x05 && enc[10] == 0x00)
                {
                    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(enc);

                    keyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(keyInfo.getAlgorithm().getAlgorithm()), keyInfo.getPublicKeyData().getBytes());

                    try
                    {
                        enc = keyInfo.getEncoded(ASN1Encoding.DER);
                    }
                    catch (IOException e)
                    {
                        throw new InvalidKeySpecException("attempt to reconstruct key failed: " + e.getMessage());
                    }
                }

                // optimise if we can
                if (specificBase == 0 || specificBase == enc[8])
                {
                    try
                    {
                        switch (enc[8])
                        {
                        case x448_type:
                            return new ProvXDHPublicKey(enc);
                        case x25519_type:
                            return new ProvXDHPublicKey(enc);
                        case Ed448_type:
                            return new ProvEdDSAPublicKey(enc);
                        case Ed25519_type:
                            return new ProvEdDSAPublicKey(enc);
                        default:
                            return super.engineGeneratePublic(keySpec);
                        }
                    }
                    catch (InvalidKeySpecException e)
                    {
                        throw e;
                    }
                    catch (Exception e)
                    {
                        throw new InvalidKeySpecException(e.getMessage(), e);
                    }
                }
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

            if (isXdh)
            {
                if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
                {
                    return new ProvXDHPrivateKey(keyInfo);
                }
                if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
                {
                    return new ProvXDHPrivateKey(keyInfo);
                }
            }
            else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return new ProvEdDSAPrivateKey(keyInfo);
                }
                if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
                {
                    return new ProvEdDSAPrivateKey(keyInfo);
                }
            }

            throw new IOException("algorithm identifier " + algOid + " in key not recognized");
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

            if (isXdh)
            {
                if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
                {
                    return new ProvXDHPublicKey(keyInfo.getEncoded());
                }
                if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
                {
                    return new ProvXDHPublicKey(keyInfo.getEncoded());
                }
            }
            else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return new ProvEdDSAPublicKey(keyInfo.getEncoded());
                }
                if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
                {
                    return new ProvEdDSAPublicKey(keyInfo.getEncoded());
                }
            }

            throw new IOException("algorithm identifier " + algOid + " in key not recognized");
        }

        static class XDH
            extends KeyFactorySpi
        {
            public XDH()
            {
                super("XDH", true, 0);
            }
        }

        static class X448
            extends KeyFactorySpi
        {
            public X448()
            {
                super("X448", true, x448_type);
            }
        }

        static class X25519
            extends KeyFactorySpi
        {
            public X25519()
            {
                super("X25519", true, x25519_type);
            }
        }

        static class EdDSA
            extends KeyFactorySpi
        {
            public EdDSA()
            {
                super("EdDSA", false, 0);
            }
        }

        static class Ed448
            extends KeyFactorySpi
        {
            public Ed448()
            {
                super("Ed448", false, Ed448_type);
            }
        }

        static class Ed25519
            extends KeyFactorySpi
        {
            public Ed25519()
            {
                super("Ed25519", false, Ed25519_type);
            }
        }
    }


    static class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider provider;
        private final boolean isXDH;

        private Parameters params;
        private AsymmetricKeyPairGenerator engine;
        private SecureRandom random;
        private boolean initialised = false;

        public KeyPairGeneratorSpi(BouncyCastleFipsProvider provider, boolean isXDH, Parameters params)
        {
            super(params != null ? params.getAlgorithm().getName() : (isXDH ? "XDH" : "EdDSA"));
            this.params = params;
            this.provider = provider;
            this.isXDH = isXDH;
        }

        public void initialize(
            int strength)
        {
            initialize(strength, provider.getDefaultSecureRandom());
        }

        public void initialize(int strength, SecureRandom secureRandom)
        {
            this.random = secureRandom;

            switch (strength)
            {
            case 255:
            case 256:
                if (isXDH)
                {
                    if (params != null && params != EdEC.X25519)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }
                    this.params = EdEC.X25519;
                }
                else
                {
                    if (params != null && params != FipsEdEC.Ed25519)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }
                    this.params = FipsEdEC.Ed25519;
                }
                break;
            case 448:
                if (isXDH)
                {
                    if (params != null && params != EdEC.X448)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }
                    this.params = EdEC.X448;
                }
                else
                {
                    if (params != null && params != FipsEdEC.Ed448)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }                       
                    this.params = FipsEdEC.Ed448;
                }
                break;
            default:
                throw new InvalidParameterException("unknown key size.");
            }
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
            if (params instanceof ECGenParameterSpec)
            {
                this.params = getParams(((ECGenParameterSpec)params).getName());
            }
            else if (!isXDH && params instanceof EdDSAParameterSpec)
            {
                this.params = getParams(((EdDSAParameterSpec)params).getCurveName());
            }
            else if (isXDH && params instanceof XDHParameterSpec)
            {
                this.params = getParams(((XDHParameterSpec)params).getCurveName());
            }
            else
            {
                if (params == null)
                {
                    throw new InvalidAlgorithmParameterException("parameterSpec cannot be null");
                }
                String name = ProvEC.getNameFrom(params);

                if (name != null)
                {
                    this.params = getParams(name);
                }
                else
                {
                    throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
                }
            }

            this.random = random;
        }

        private Parameters getParams(String name)
            throws InvalidAlgorithmParameterException
        {
            if (isXDH)
            {
                if (name.equalsIgnoreCase(XDHParameterSpec.X448) || name.equals(EdECObjectIdentifiers.id_X448.getId()))
                {
                    return EdEC.X448;
                }
                if (name.equalsIgnoreCase(XDHParameterSpec.X25519) || name.equals(EdECObjectIdentifiers.id_X25519.getId()))
                {
                    return EdEC.X25519;
                }
                throw new InvalidAlgorithmParameterException("unknown curve name: " + name);
            }
            else
            {
                if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed448) || name.equals(EdECObjectIdentifiers.id_Ed448.getId()))
                {
                    return FipsEdEC.Ed448;
                }
                if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed25519) || name.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
                {
                    return FipsEdEC.Ed25519;
                }
                throw new InvalidAlgorithmParameterException("unknown curve name: " + name);
            }
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                if (params == null)
                {
                    throw new IllegalStateException("generator not correctly initialized");
                }

                if (random == null)
                {
                    random = provider.getDefaultSecureRandom();
                }

                if (isXDH)
                {
                    engine = new EdEC.XDHKeyPairGenerator((EdEC.Parameters)params, random);
                }
                else
                {
                    engine = new FipsEdEC.EdDSAKeyPairGenerator((FipsEdEC.Parameters)params, random);
                }
                initialised = true;
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();

            if (isXDH)
            {
                AsymmetricXDHPublicKey pub = (AsymmetricXDHPublicKey)pair.getPublicKey();
                AsymmetricXDHPrivateKey priv = (AsymmetricXDHPrivateKey)pair.getPrivateKey();

                return new KeyPair(new ProvXDHPublicKey(pub), new ProvXDHPrivateKey(priv));
            }
            else
            {
                AsymmetricEdDSAPublicKey pub = (AsymmetricEdDSAPublicKey)pair.getPublicKey();
                AsymmetricEdDSAPrivateKey priv = (AsymmetricEdDSAPrivateKey)pair.getPrivateKey();

                return new KeyPair(new ProvEdDSAPublicKey(pub), new ProvEdDSAPrivateKey(priv, pub));
            }
        }
    }

    static class XDHParametersCreator
        implements ParametersCreator
    {
        private final EdEC.Parameters params;

        XDHParametersCreator(EdEC.Parameters params)
        {
            this.params = params;
        }

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (spec != null)
            {
                throw new InvalidAlgorithmParameterException("unable to take parameter specs");
            }
            return params;
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyFactory.XDH", PREFIX + "KeyFactorySpi$XDH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.XDH();
            }
        }));
        provider.addAlgorithmImplementation("KeyFactory.X448", PREFIX + "KeyFactorySpi$X448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.X448();
            }
        }));
        provider.addAlgorithmImplementation("KeyFactory.X25519", PREFIX + "KeyFactorySpi$X25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.X25519();
            }
        }));

        provider.addAlgorithmImplementation("KeyFactory.EDDSA", PREFIX + "KeyFactorySpi$EdDH", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.EdDSA();
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.ED448", PREFIX + "KeyFactorySpi$Ed448", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.Ed448();
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.ED25519", PREFIX + "KeyFactorySpi$Ed25519", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.Ed25519();
            }
        });

        provider.addAlgorithmImplementation("KeyPairGenerator.EDDSA", PREFIX + "KeyPairGeneratorSpi$EdDSA", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, false, null);
            }
        });

        provider.addAlgorithmImplementation("KeyPairGenerator.ED448", PREFIX + "KeyPairGeneratorSpi$Ed448", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, false, FipsEdEC.Ed448);
            }
        });

        provider.addAlgorithmImplementation("KeyPairGenerator.ED25519", PREFIX + "KeyPairGeneratorSpi$Ed25519", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, false, FipsEdEC.Ed25519);
            }
        });

        provider.addAlgorithmImplementation("KeyPairGenerator.XDH", PREFIX + "KeyPairGeneratorSpi$XDH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, true,null);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.X448", PREFIX + "KeyPairGeneratorSpi$X448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, true, EdEC.X448);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.X25519", PREFIX + "KeyPairGeneratorSpi$X25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, true, EdEC.X25519);
            }
        }));

        provider.addAlgorithmImplementation("Signature.EDDSA", PREFIX + "Signature$EDDSA", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new FipsEdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, FipsEdEC.EdDSA);
            }
        });

        provider.addAlgorithmImplementation("Signature.EDDSAPH", PREFIX + "Signature$EDDSAPH", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new FipsEdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, FipsEdEC.EdDSAph);
            }
        });

        provider.addAlgorithmImplementation("Signature.ED448", PREFIX + "Signature$Ed448", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new FipsEdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, FipsEdEC.Ed448);
            }
        });
        provider.addAlias("Signature", "ED448", EdECObjectIdentifiers.id_Ed448);

        provider.addAlgorithmImplementation("Signature.ED448PH", PREFIX + "Signature$Ed448Ph", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new FipsEdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, FipsEdEC.Ed448ph);
            }
        });

        provider.addAlgorithmImplementation("Signature.ED25519", PREFIX + "Signature$Ed25519", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new FipsEdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, FipsEdEC.Ed25519);
            }
        });
        provider.addAlias("Signature", "ED25519", EdECObjectIdentifiers.id_Ed25519);

        provider.addAlgorithmImplementation("Signature.ED25519PH", PREFIX + "Signature$Ed25519Ph", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new FipsEdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, FipsEdEC.Ed25519ph);
            }
        });

        addKeyAgreementAlgorithm(provider, "X448", PREFIX + "KeyAgreementSpi$X448", generalXDHAttributes, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(xdhFactory, xPublicKeyConverter, xPrivateKeyConverter, new XDHParametersCreator(EdEC.X448));
            }
        }));
        provider.addAlias("KeyAgreement", "X448", EdECObjectIdentifiers.id_X448);

        final ParametersCreator x448CParametersCreator = new ParametersCreator()
        {

            public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                throws InvalidAlgorithmParameterException
            {
                if (spec != null && !(spec instanceof UserKeyingMaterialSpec))
                {
                    throw new InvalidAlgorithmParameterException("X448 can only take a UserKeyingMaterialSpec");
                }
                return EdEC.X448;
            }
        };

        addCDHAlgorithm(provider, "X448", "SHA224", FipsKDF.AgreementKDFPRF.SHA224, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA256", FipsKDF.AgreementKDFPRF.SHA256, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA384", FipsKDF.AgreementKDFPRF.SHA384, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA512", FipsKDF.AgreementKDFPRF.SHA512, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384, x448CParametersCreator);
        addCDHAlgorithm(provider, "X448", "SHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512, x448CParametersCreator);

        addKeyAgreementAlgorithm(provider, "X25519", PREFIX + "KeyAgreementSpi$X25519", generalXDHAttributes, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(new EdEC.XDHAgreementFactory(), xPublicKeyConverter, xPrivateKeyConverter, new XDHParametersCreator(EdEC.X25519));
            }
        }));
        provider.addAlias("KeyAgreement", "X25519", EdECObjectIdentifiers.id_X25519);

        final ParametersCreator x25519CParametersCreator = new ParametersCreator()
        {

            public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                throws InvalidAlgorithmParameterException
            {
                if (spec != null && !(spec instanceof UserKeyingMaterialSpec))
                {
                    throw new InvalidAlgorithmParameterException("X25519 can only take a UserKeyingMaterialSpec");
                }
                return EdEC.X25519;
            }
        };

        addCDHAlgorithm(provider, "X25519", "SHA224", FipsKDF.AgreementKDFPRF.SHA224, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA256", FipsKDF.AgreementKDFPRF.SHA256, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA384", FipsKDF.AgreementKDFPRF.SHA384, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA512", FipsKDF.AgreementKDFPRF.SHA512, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384, x25519CParametersCreator);
        addCDHAlgorithm(provider, "X25519", "SHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512, x25519CParametersCreator);

        registerOid(provider, EdECObjectIdentifiers.id_X448, "X448", new KeyFactorySpi.X448());
        registerOid(provider, EdECObjectIdentifiers.id_X25519, "X25519", new KeyFactorySpi.X25519());
        registerOid(provider, EdECObjectIdentifiers.id_Ed448, "ED448", new KeyFactorySpi.Ed448());
        registerOid(provider, EdECObjectIdentifiers.id_Ed25519, "ED25519", new KeyFactorySpi.Ed25519());
    }

    private void addCDHAlgorithm(BouncyCastleFipsProvider provider, String curveName, String digestName, final FipsKDF.AgreementKDFPRF prf, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = curveName + "WITH" + digestName + "CKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalXDHAttributes, new GuardedEngineCreator(
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseAgreement(xdhFactory, xPublicKeyConverter, xPrivateKeyConverter, cdhParametersCreator, FipsKDF.CONCATENATION.withPRF(prf));
                }
            }));
    }
}
