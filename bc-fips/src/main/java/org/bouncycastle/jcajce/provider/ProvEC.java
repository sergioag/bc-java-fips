package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AgreementFactory;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SignatureOperatorFactory;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersID;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersIndex;
import org.bouncycastle.crypto.asymmetric.ECImplicitDomainParameters;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.EC;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.TwoStepKDFParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;

class ProvEC
    extends AsymmetricAlgorithmProvider
{
    private static AgreementFactory fipsDHFactory;
    private static AgreementFactory fipsDHUFactory;
    private static AgreementFactory fipsMQVFactory;
    private static SignatureOperatorFactory fipsDsaFactory;

    private static final Map<String, String> generalEcAttributes = new HashMap<String, String>();

    private static final String PREFIX = ProvEC.class.getName() + ".";

    private static SignatureOperatorFactory genDsaFactory;

    // used to avoid early loading of FipsEC (blinding/securerandom issue)
    private enum EC_Algorithm
    {
        DSA,
        DH,
        EC,
        CDH,
        MQV
    }

    static
    {
        generalEcAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalEcAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    // lazy init required to avoid SecureRandom issues due to blinding KAT
    private static AgreementFactory getFipsDHFactory()
    {
        if (!Properties.isOverrideSet("org.bouncycastle.ec.disable"))
        {
            fipsDHFactory = new FipsEC.DHAgreementFactory();
        }
        
        return fipsDHFactory;
    }
    
    private static AgreementFactory getFipsDHUFactory()
    {
        if (!Properties.isOverrideSet("org.bouncycastle.ec.disable"))
        {
            fipsDHUFactory = new FipsEC.DHUAgreementFactory();
        }
        
        return fipsDHUFactory;
    }
    
    private static AgreementFactory getFipsMQVFactory()
    {
        if (!Properties.isOverrideSet("org.bouncycastle.ec.disable"))
        {
            fipsMQVFactory = Properties.isOverrideSet("org.bouncycastle.ec.disable_mqv") ? null : new FipsEC.MQVAgreementFactory();
        }
        
        return fipsMQVFactory;
    }
    
    private static SignatureOperatorFactory getFipsDSAFactory()
    {
        if (!Properties.isOverrideSet("org.bouncycastle.ec.disable"))
        {
            fipsDsaFactory = new FipsEC.DSAOperatorFactory();
        }
        
        return fipsDsaFactory;
    }
    
    private static SignatureOperatorFactory getGeneralDSAFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (genDsaFactory == null)
        {
            genDsaFactory = new EC.DSAOperatorFactory();
        }

        return genDsaFactory;
    }

    private static Algorithm getAlgorithm(EC_Algorithm alg)
    {
        switch (alg)
        {
        case DSA:
            return FipsEC.DSA.getAlgorithm();
        case DH:
            return FipsEC.DH.getAlgorithm();
        case CDH:
            return FipsEC.CDH.getAlgorithm();
        case MQV:
            return FipsEC.MQV.getAlgorithm();
        }

        return FipsEC.ALGORITHM;
    }

    private static final PublicKeyConverter<AsymmetricECPublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricECPublicKey>()
    {
        public AsymmetricECPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ECPublicKey)
            {
                if (key instanceof ProvECPublicKey)
                {
                    return ((ProvECPublicKey)key).getBaseKey();
                }
                return new ProvECPublicKey(algorithm, (ECPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricECPublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify EC public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricECPrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricECPrivateKey>()
    {
        public AsymmetricECPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ECPrivateKey)
            {
                if (key instanceof ProvECPrivateKey)
                {
                    return ((ProvECPrivateKey)key).getBaseKey();
                }
                return new ProvECPrivateKey(algorithm, (ECPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricECPrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify EC private key: " + e.getMessage(), e);
                }
            }
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("AlgorithmParameters.EC", PREFIX + "AlgorithmParametersSpi$EC", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECAlgParams();
            }
        });

        final ParametersCreator dhParametersCreator = new ParametersCreator()
        {

            public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                throws InvalidAlgorithmParameterException
            {
                if (spec != null && !(spec instanceof UserKeyingMaterialSpec))
                {
                    throw new InvalidAlgorithmParameterException("ECDH can only take a UserKeyingMaterialSpec");
                }
                return FipsEC.DH;
            }
        };

        final ParametersCreator cdhParametersCreator = new ParametersCreator()
        {
            public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                throws InvalidAlgorithmParameterException
            {
                if (spec != null && !(spec instanceof UserKeyingMaterialSpec))
                {
                    throw new InvalidAlgorithmParameterException("ECCDH can only take a UserKeyingMaterialSpec");
                }
                return FipsEC.CDH;
            }
        };

        final ParametersCreator cdhTwoStepParametersCreator = new ParametersCreator()
        {
            public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                throws InvalidAlgorithmParameterException
            {
                if (spec != null && !(spec instanceof TwoStepKDFParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("TwoStep KDF requires a TwoStepKDFParameterSpec");
                }
                return FipsEC.CDH;
            }
        };

        final ParametersCreator cdhuParametersCreator = new DhuParamsCreator(false);
        final ParametersCreator cdhuTSParametersCreator = new DhuParamsCreator(true);

        provider.addAlgorithmImplementation("KeyFactory.EC", PREFIX + "KeyFactorySpi$EC", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyFactory(EC_Algorithm.EC);
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.ECDSA", PREFIX + "KeyFactorySpi$ECDSA", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyFactory(EC_Algorithm.DSA);
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.ECDH", PREFIX + "KeyFactorySpi$ECDH", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyFactory(EC_Algorithm.DH);
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.ECCDH", PREFIX + "KeyFactorySpi$ECCDH", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyFactory(EC_Algorithm.CDH);
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.ECMQV", PREFIX + "KeyFactorySpi$ECMQV", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyFactory(EC_Algorithm.MQV);
            }
        });

        provider.addAlgorithmImplementation("KeyPairGenerator.EC", PREFIX + "KeyPairGeneratorSpi$EC", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyPairGenerator(provider, FipsEC.ALGORITHM);
            }
        });
        provider.addAlgorithmImplementation("KeyPairGenerator.ECDSA", PREFIX + "KeyPairGeneratorSpi$ECDSA", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyPairGenerator(provider, FipsEC.DSA);
            }
        });
        provider.addAlgorithmImplementation("KeyPairGenerator.ECDH", PREFIX + "KeyPairGeneratorSpi$ECDH", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyPairGenerator(provider, FipsEC.DH);
            }
        });
        provider.addAlgorithmImplementation("KeyPairGenerator.ECCDH", PREFIX + "KeyPairGeneratorSpi$ECCDH", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyPairGenerator(provider, FipsEC.CDH);
            }
        });
        provider.addAlgorithmImplementation("KeyPairGenerator.ECMQV", PREFIX + "KeyPairGeneratorSpi$ECMQV", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ECKeyPairGenerator(provider, FipsEC.MQV);
            }
        });

        registerOid(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC", new ECKeyFactory(EC_Algorithm.DSA));

        addKeyAgreementAlgorithm(provider, "ECDH", PREFIX + "KeyAgreementSpi$DH", generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHFactory(), publicKeyConverter, privateKeyConverter, dhParametersCreator);
            }
        });
        addKeyAgreementAlgorithm(provider, "ECCDH", PREFIX + "KeyAgreementSpi$CDH", generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator);
            }
        });
        provider.addAlias("Alg.Alias.KeyAgreement.ECDHC", "ECCDH");

        AsymmetricKeyInfoConverter converter = new ECKeyFactory(EC_Algorithm.DH);

        addDHAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, converter, dhParametersCreator);
        addDHAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, converter, dhParametersCreator);
        addDHAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, converter, dhParametersCreator);
        addDHAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, converter, dhParametersCreator);
        addDHAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, converter, dhParametersCreator);

        converter = new ECKeyFactory(EC_Algorithm.CDH);

        addCDHAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, converter, cdhParametersCreator);
        addCDHAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, converter, cdhParametersCreator);
        addCDHAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, converter, cdhParametersCreator);
        addCDHAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, converter, cdhParametersCreator);
        addCDHAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, converter, cdhParametersCreator);
        addCDHAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, null, converter, cdhParametersCreator);
        addCDHAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, null, converter, cdhParametersCreator);

        addConcatCDHAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "SHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA224", FipsKDF.AgreementKDFPRF.SHA224_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA256", FipsKDF.AgreementKDFPRF.SHA256_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA384", FipsKDF.AgreementKDFPRF.SHA384_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA512", FipsKDF.AgreementKDFPRF.SHA512_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "HMACSHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512_HMAC, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "KMAC-128", FipsKDF.AgreementKDFPRF.KMAC_128, cdhParametersCreator);
        addConcatCDHAlgorithm(provider, "KMAC-256", FipsKDF.AgreementKDFPRF.KMAC_256, cdhParametersCreator);

        addTwoStepCDHAlgorithm(provider, "CMAC", FipsKDF.PRF.AES_CMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA1", FipsKDF.PRF.SHA1_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA224", FipsKDF.PRF.SHA224_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA256", FipsKDF.PRF.SHA256_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA384", FipsKDF.PRF.SHA384_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA512", FipsKDF.PRF.SHA512_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA512(224)", FipsKDF.PRF.SHA512_224_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA512(256)", FipsKDF.PRF.SHA512_256_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA3-224", FipsKDF.PRF.SHA3_224_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA3-256", FipsKDF.PRF.SHA3_256_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA3-384", FipsKDF.PRF.SHA3_384_HMAC, cdhTwoStepParametersCreator);
        addTwoStepCDHAlgorithm(provider, "HMACSHA3-512", FipsKDF.PRF.SHA3_512_HMAC, cdhTwoStepParametersCreator);

        addCDHUAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, cdhuParametersCreator);
        addCDHUAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, cdhuParametersCreator);
        addCDHUAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, cdhuParametersCreator);
        addCDHUAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, cdhuParametersCreator);
        addCDHUAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, cdhuParametersCreator);
        addCDHUAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, cdhuParametersCreator);
        addCDHUAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, cdhuParametersCreator);

        addConcatCDHUAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "SHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA224", FipsKDF.AgreementKDFPRF.SHA224_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA256", FipsKDF.AgreementKDFPRF.SHA256_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA384", FipsKDF.AgreementKDFPRF.SHA384_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA512", FipsKDF.AgreementKDFPRF.SHA512_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "HMACSHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512_HMAC, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "KMAC-128", FipsKDF.AgreementKDFPRF.KMAC_128, cdhuParametersCreator);
        addConcatCDHUAlgorithm(provider, "KMAC-256", FipsKDF.AgreementKDFPRF.KMAC_256, cdhuParametersCreator);

        addTwoStepCDHUAlgorithm(provider, "CMAC", FipsKDF.PRF.AES_CMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA1", FipsKDF.PRF.SHA1_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA224", FipsKDF.PRF.SHA224_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA256", FipsKDF.PRF.SHA256_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA384", FipsKDF.PRF.SHA384_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA512", FipsKDF.PRF.SHA512_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA512(224)", FipsKDF.PRF.SHA512_224_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA512(256)", FipsKDF.PRF.SHA512_256_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA3-224", FipsKDF.PRF.SHA3_224_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA3-256", FipsKDF.PRF.SHA3_256_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA3-384", FipsKDF.PRF.SHA3_384_HMAC, cdhuTSParametersCreator);
        addTwoStepCDHUAlgorithm(provider, "HMACSHA3-512", FipsKDF.PRF.SHA3_512_HMAC, cdhuTSParametersCreator);

        provider.addAlgorithmImplementation("Signature.NONEWITHECDSA", PREFIX + "SignatureSpi$ecDSAwithNONE", generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(null));
            }
        });
        provider.addAlias("Signature", "NONEWITHECDSA", "RAWECDSA");

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Signature.SHA1WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA1));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA224WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA224", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA224));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA256WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA256", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA256));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA384WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA384", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA384));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA512WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA512", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA512(224)WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA512_224", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_224));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA512(256)WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA512_256", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_256));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA3-224WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA3_224", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_224));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA3-256WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA3_256", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_256));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA3-384WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA3_384", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_384));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA3-512WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA3_512", generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_512));
                }
            }));

            provider.addAlias("Alg.Alias.Signature.ECDDSA", "SHA1WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.DETECDSA", "SHA1WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA1WITHDETECDSA", "SHA1WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA224WITHDETECDSA", "SHA224WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA256WITHDETECDSA", "SHA256WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA384WITHDETECDSA", "SHA384WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA512WITHDETECDSA", "SHA512WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA512(224)WITHDETECDSA", "SHA512(224)WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA512(256)WITHDETECDSA", "SHA512(256)WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA3-224WITHDETECDSA", "SHA3-224WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA3-256WITHDETECDSA", "SHA3-256WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA3-384WITHDETECDSA", "SHA3-384WITHECDDSA");
            provider.addAlias("Alg.Alias.Signature.SHA3-512WITHDETECDSA", "SHA3-512WITHECDDSA");
        }

        addSignatureAlgorithm(provider, "SHA1", "ECDSA", PREFIX + "SignatureSpi$ecDSA1", X9ObjectIdentifiers.ecdsa_with_SHA1, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA1));
            }
        });
        provider.addAlias("Signature", "SHA1WITHECDSA", "ECDSA");
        provider.addAlias("Signature", "SHA1WITHECDSA", TeleTrusTObjectIdentifiers.ecSignWithSha1);

        addSignatureAlgorithm(provider, "SHA224", "ECDSA", PREFIX + "SignatureSpi$ecDSA224", X9ObjectIdentifiers.ecdsa_with_SHA224, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA224));
            }
        });
        addSignatureAlgorithm(provider, "SHA256", "ECDSA", PREFIX + "SignatureSpi$ecDSA256", X9ObjectIdentifiers.ecdsa_with_SHA256, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA256));
            }
        });
        addSignatureAlgorithm(provider, "SHA384", "ECDSA", PREFIX + "SignatureSpi$ecDSA384", X9ObjectIdentifiers.ecdsa_with_SHA384, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA384));
            }
        });
        addSignatureAlgorithm(provider, "SHA512", "ECDSA", PREFIX + "SignatureSpi$ecDSA512", X9ObjectIdentifiers.ecdsa_with_SHA512, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512));
            }
        });
        addSignatureAlgorithm(provider, "SHA512(224)", "ECDSA", PREFIX + "SignatureSpi$ecDSA512_224", null, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_224));
            }
        });
        addSignatureAlgorithm(provider, "SHA512(256)", "ECDSA", PREFIX + "SignatureSpi$ecDSA512_256", null, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_256));
            }
        });
        addSignatureAlgorithm(provider, "SHA3-224", "ECDSA", PREFIX + "SignatureSpi$ecDSA3_224", NISTObjectIdentifiers.id_ecdsa_with_sha3_224, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_224));
            }
        });
        addSignatureAlgorithm(provider, "SHA3-256", "ECDSA", PREFIX + "SignatureSpi$ecDSA3_256", NISTObjectIdentifiers.id_ecdsa_with_sha3_256, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_256));
            }
        });
        addSignatureAlgorithm(provider, "SHA3-384", "ECDSA", PREFIX + "SignatureSpi$ecDSA3_384", NISTObjectIdentifiers.id_ecdsa_with_sha3_384, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_384));
            }
        });
        addSignatureAlgorithm(provider, "SHA3-512", "ECDSA", PREFIX + "SignatureSpi$ecDSA3_512", NISTObjectIdentifiers.id_ecdsa_with_sha3_512, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, getFipsDSAFactory(), publicKeyConverter, privateKeyConverter, FipsEC.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA3_512));
            }
        });

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            addSignatureAlgorithm(provider, "RIPEMD160", "ECDSA", PREFIX + "SignatureSpi$ecDSARipeMD160", TeleTrusTObjectIdentifiers.ecSignWithRipemd160, generalEcAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, EC.DSA.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD160));
                }
            }));
        }

        if (!Properties.isOverrideSet("org.bouncycastle.ec.disable_mqv"))
        {
            converter = new ECKeyFactory(EC_Algorithm.MQV);
            final ParametersCreator mqvParametersCreator = new MqvParamsCreator(false);

            addKeyAgreementAlgorithm(provider, "ECMQV", PREFIX + "KeyAgreementSpi$ECMQV", generalEcAttributes, new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseAgreement(getFipsMQVFactory(), publicKeyConverter, privateKeyConverter, mqvParametersCreator);
                }
            });

            addMQVAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, converter, mqvParametersCreator);
            addMQVAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, converter, mqvParametersCreator);
            addMQVAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, converter, mqvParametersCreator);
            addMQVAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, converter, mqvParametersCreator);
            addMQVAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, converter, mqvParametersCreator);
            addMQVAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, null, converter, mqvParametersCreator);
            addMQVAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, null, converter, mqvParametersCreator);

            addConcatMQVAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA224", FipsKDF.AgreementKDFPRF.SHA224_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA256", FipsKDF.AgreementKDFPRF.SHA256_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA384", FipsKDF.AgreementKDFPRF.SHA384_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA512", FipsKDF.AgreementKDFPRF.SHA512_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "SHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA3-224", FipsKDF.AgreementKDFPRF.SHA3_224_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA3-256", FipsKDF.AgreementKDFPRF.SHA3_256_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA3-384", FipsKDF.AgreementKDFPRF.SHA3_384_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "HMACSHA3-512", FipsKDF.AgreementKDFPRF.SHA3_512_HMAC, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "KMAC-128", FipsKDF.AgreementKDFPRF.KMAC_128, mqvParametersCreator);
            addConcatMQVAlgorithm(provider, "KMAC-256", FipsKDF.AgreementKDFPRF.KMAC_256, mqvParametersCreator);

            final ParametersCreator mqvTSParametersCreator = new MqvParamsCreator(true);

            addTwoStepMQVAlgorithm(provider, "CMAC", FipsKDF.PRF.AES_CMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA1", FipsKDF.PRF.SHA1_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA224", FipsKDF.PRF.SHA224_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA256", FipsKDF.PRF.SHA256_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA384", FipsKDF.PRF.SHA384_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA512", FipsKDF.PRF.SHA512_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA512(224)", FipsKDF.PRF.SHA512_224_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA512(256)", FipsKDF.PRF.SHA512_256_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA3-224", FipsKDF.PRF.SHA3_224_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA3-256", FipsKDF.PRF.SHA3_256_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA3-384", FipsKDF.PRF.SHA3_384_HMAC, mqvTSParametersCreator);
            addTwoStepMQVAlgorithm(provider, "HMACSHA3-512", FipsKDF.PRF.SHA3_512_HMAC, mqvTSParametersCreator);
        }
    }

    private void addDHAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, ASN1ObjectIdentifier algOid, AsymmetricKeyInfoConverter converter, final ParametersCreator dhParametersCreator)
    {
        String algorithm = "ECDHWITH" + digestName + "KDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHFactory(), publicKeyConverter, privateKeyConverter, dhParametersCreator, FipsKDF.X963.withPRF(prf));
            }
        });
        if (algOid != null)
        {
            provider.addAlias("KeyAgreement", algorithm, algOid);
            registerOid(provider, algOid, "ECDH", converter);
            provider.addAlias("AlgorithmParameters", "EC", algOid);
        }
    }

    private void addCDHAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, ASN1ObjectIdentifier algOid, AsymmetricKeyInfoConverter converter, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = "ECCDHWITH" + digestName + "KDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator, FipsKDF.X963.withPRF(prf));
            }
        });
        if (algOid != null)
        {
            provider.addAlias("KeyAgreement", algorithm, algOid);
            registerOid(provider, algOid, "ECCDH", converter);
            provider.addAlias("AlgorithmParameters", "EC", algOid);
        }
    }

    private void addConcatCDHAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = "ECCDHWITH" + digestName + "CKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator, FipsKDF.CONCATENATION.withPRF(prf));
            }
        });
    }

    private void addTwoStepCDHAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.PRF prf, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = "ECCDHWITH" + digestName + "TSKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator, FipsKDF.TWO_STEP_KEY_BUILDER.withPRF(prf));
            }
        });
    }

    private void addCDHUAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = "ECCDHUWITH" + digestName + "KDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHUFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator, FipsKDF.X963.withPRF(prf));
            }
        });
    }

    private void addConcatCDHUAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = "ECCDHUWITH" + digestName + "CKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHUFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator, FipsKDF.CONCATENATION.withPRF(prf));
            }
        });
    }

    private void addTwoStepCDHUAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.PRF prf, final ParametersCreator cdhParametersCreator)
    {
        String algorithm = "ECCDHUWITH" + digestName + "TSKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsDHUFactory(), publicKeyConverter, privateKeyConverter, cdhParametersCreator, FipsKDF.TWO_STEP_KEY_BUILDER.withPRF(prf));
            }
        });
    }

    private void addMQVAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, ASN1ObjectIdentifier algOid, AsymmetricKeyInfoConverter converter, final ParametersCreator mqvParametersCreator)
    {
        String algorithm = "ECMQVWITH" + digestName + "KDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsMQVFactory(), publicKeyConverter, privateKeyConverter, mqvParametersCreator, FipsKDF.X963.withPRF(prf));
            }
        });

        if (algOid != null)
        {
            provider.addAlias("KeyAgreement", algorithm, algOid);
            registerOid(provider, algOid, "EC", converter);
            provider.addAlias("AlgorithmParameters", "EC", algOid);
        }
    }

    private void addConcatMQVAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.AgreementKDFPRF prf, final ParametersCreator mqvParametersCreator)
    {
        String algorithm = "ECMQVWITH" + digestName + "CKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsMQVFactory(), publicKeyConverter, privateKeyConverter, mqvParametersCreator, FipsKDF.CONCATENATION.withPRF(prf));
            }
        });
    }

    private void addTwoStepMQVAlgorithm(BouncyCastleFipsProvider provider, String digestName, final FipsKDF.PRF prf, final ParametersCreator mqvParametersCreator)
    {
        String algorithm = "ECMQVWITH" + digestName + "TSKDF";
        addKeyAgreementAlgorithm(provider, algorithm, PREFIX + "KeyAgreementSpi$" + algorithm, generalEcAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(getFipsMQVFactory(), publicKeyConverter, privateKeyConverter, mqvParametersCreator, FipsKDF.TWO_STEP_KEY_BUILDER.withPRF(prf));
            }
        });
    }

    static class ECAlgParams
        extends X509AlgorithmParameters
    {
        private ECDomainParameters domainParameters = ECDomainParametersIndex.lookupDomainParameters(SECObjectIdentifiers.secp521r1);

        @Override
        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (ECParameterSpec.class.isAssignableFrom(paramSpec) || paramSpec == AlgorithmParameterSpec.class)
            {
                return ECUtil.convertToSpec(domainParameters);
            }
            else if (ECGenParameterSpec.class.isAssignableFrom(paramSpec))
            {
                if (domainParameters instanceof NamedECDomainParameters)
                {
                    return new ECGenParameterSpec(((NamedECDomainParameters)domainParameters).getID().getId());
                }
                else
                {
                    ASN1ObjectIdentifier oid = ECDomainParametersIndex.lookupOID(domainParameters);
                    if (oid != null)
                    {
                        return new ECGenParameterSpec(oid.getId());
                    }
                    else
                    {
                        throw new InvalidParameterSpecException("Cannot identify curve in AlgorithmParameters by name");
                    }
                }
            }
            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        @Override
        protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException
        {
            if (algorithmParameterSpec instanceof ECGenParameterSpec)
            {
                final ECGenParameterSpec spec = (ECGenParameterSpec)algorithmParameterSpec;

                domainParameters = getDomainParametersFromName(spec.getName());
                if (domainParameters == null)
                {
                    throw new InvalidParameterSpecException("EC AlgorithmParameters cannot recognize curve " + spec.getName());
                }
            }
            else if (algorithmParameterSpec instanceof ECDomainParameterSpec)
            {
                domainParameters = ((ECDomainParameterSpec)algorithmParameterSpec).getDomainParameters();
            }
            else if (algorithmParameterSpec instanceof ECParameterSpec)
            {
                domainParameters = ECUtil.convertFromSpec((ECParameterSpec)algorithmParameterSpec);
            }
            else
            {
                if (algorithmParameterSpec == null)
                {
                    throw new InvalidParameterSpecException("parameterSpec cannot be null");
                }
                String name = getNameFrom(algorithmParameterSpec);

                if (name != null)
                {
                    domainParameters = getDomainParametersFromName(name);
                    if (domainParameters == null)
                    {
                        throw new InvalidParameterSpecException("unknown curve ID: " + name);
                    }
                }
                else
                {
                    throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + algorithmParameterSpec.getClass().getName());
                }
            }
        }

        protected void localInit(byte[] encoding)
            throws IOException
        {
            domainParameters = decodeCurveParameters(encoding);
        }

        protected byte[] localGetEncoded()
            throws IOException
        {
            X962Parameters params;

            if (domainParameters instanceof NamedECDomainParameters)
            {
                params = new X962Parameters(((NamedECDomainParameters)domainParameters).getID());
            }
            else if (domainParameters instanceof ECImplicitDomainParameters)     // implicitly CA
            {
                params = new X962Parameters(DERNull.INSTANCE);
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                    domainParameters.getCurve(),
                    new X9ECPoint(domainParameters.getG(), false),
                    domainParameters.getN(),
                    domainParameters.getH(),
                    domainParameters.getSeed());

                params = new X962Parameters(ecP);
            }

            return params.getEncoded();
        }

        private static ECDomainParameters decodeCurveParameters(byte[] encoding)
            throws IOException
        {
            X962Parameters params = X962Parameters.getInstance(encoding);

            X9ECParameters x9;

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();
                return ECDomainParametersIndex.lookupDomainParameters(oid);
            }
            else if (!params.isImplicitlyCA())
            {
                x9 = X9ECParameters.getInstance(params.getParameters());
                return new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
            }
            else
            {
                ECDomainParameters ecDomainParameters = CryptoServicesRegistrar.getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA);

                if (ecDomainParameters == null)
                {
                    throw new IOException("Encoding indicates implicitlyCA but CryptoServicesRegistrar.getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA) returns null");
                }

                return new ECImplicitDomainParameters(ecDomainParameters);
            }
        }

        protected String engineToString()
        {
            return "EC AlgorithmParameters " + domainParameters;
        }
    }

    static class ECKeyFactory
        extends BaseKeyFactory
        implements AsymmetricKeyInfoConverter
    {
        private final EC_Algorithm algorithm;

        ECKeyFactory(
            EC_Algorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            Algorithm alg = getAlgorithm(algorithm);

            if (key instanceof PublicKey)
            {
                return new ProvECPublicKey(publicKeyConverter.convertKey(alg, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvECPrivateKey(privateKeyConverter.convertKey(alg, (PrivateKey)key));
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

            if (spec.isAssignableFrom(ECPublicKeySpec.class) && key instanceof ECPublicKey)
            {
                ECPublicKey k = (ECPublicKey)key;
                if (k.getParams() != null)
                {
                    return new ECPublicKeySpec(k.getW(), k.getParams());
                }
            }
            else if (spec.isAssignableFrom(ECPrivateKeySpec.class) && key instanceof ECPrivateKey)
            {
                ECPrivateKey k = (ECPrivateKey)key;

                if (k.getParams() != null)
                {
                    return new ECPrivateKeySpec(k.getS(), k.getParams());
                }
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            Algorithm alg = getAlgorithm(algorithm);
            if (keySpec instanceof ECPrivateKeySpec)
            {
                try
                {
                    return new ProvECPrivateKey(alg, (ECPrivateKeySpec)keySpec);
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            Algorithm alg = getAlgorithm(algorithm);
            if (keySpec instanceof ECPublicKeySpec)
            {
                try
                {
                    return new ProvECPublicKey(alg, (ECPublicKeySpec)keySpec);
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            Algorithm alg = getAlgorithm(algorithm);
            return new ProvECPrivateKey(new AsymmetricECPrivateKey(alg, keyInfo));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            Algorithm alg = getAlgorithm(algorithm);
            return new ProvECPublicKey(new AsymmetricECPublicKey(alg, keyInfo));
        }
    }

    static class ECKeyPairGenerator
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private final Algorithm algorithmType;
        private final Parameters parameters;

        private AsymmetricKeyPairGenerator engine;
        private int strength = 224;
        private boolean initialised = false;

        static private Hashtable ecParameters;

        static
        {
            ecParameters = new Hashtable();

            ecParameters.put(Integers.valueOf(192), new ECGenParameterSpec("prime192v1")); // a.k.a P-192
            ecParameters.put(Integers.valueOf(239), new ECGenParameterSpec("prime239v1"));
            ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec("prime256v1")); // a.k.a P-256

            ecParameters.put(Integers.valueOf(224), new ECGenParameterSpec("P-224"));
            ecParameters.put(Integers.valueOf(384), new ECGenParameterSpec("P-384"));
            ecParameters.put(Integers.valueOf(521), new ECGenParameterSpec("P-521"));
        }

        public ECKeyPairGenerator(BouncyCastleFipsProvider fipsProvider, Algorithm algorithmType)
        {
            this(fipsProvider, algorithmType, null);
        }

        public ECKeyPairGenerator(BouncyCastleFipsProvider fipsProvider, Parameters parameters)
        {
            this(fipsProvider, parameters.getAlgorithm(), parameters);
        }

        public ECKeyPairGenerator(BouncyCastleFipsProvider fipsProvider, Algorithm algorithmType, Parameters parameters)
        {
            super(algorithmType.getName());
            this.fipsProvider = fipsProvider;
            this.algorithmType = algorithmType;
            this.parameters = parameters;
        }

        public void initialize(
            int strength)
        {
            initialize(strength, fipsProvider.getDefaultSecureRandom());
        }

        public void initialize(
            int strength,
            SecureRandom random)
        {
            this.strength = strength;
            ECGenParameterSpec ecParams = (ECGenParameterSpec)ecParameters.get(Integers.valueOf(strength));

            if (ecParams != null)
            {
                try
                {
                    initialize(ecParams, random);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new InvalidParameterException("key size not configurable.");
                }
            }
            else
            {
                throw new InvalidParameterException("Key size " + strength + " bits not available");
            }
        }

        public void initialize(
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            initialize(params, fipsProvider.getDefaultSecureRandom());
        }

        public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            ECDomainParameters domainParameters;

            if (random == null)
            {
                random = fipsProvider.getDefaultSecureRandom();
            }

            if (params instanceof java.security.spec.ECParameterSpec)
            {
                domainParameters = ECUtil.convertFromSpec((java.security.spec.ECParameterSpec)params);
            }
            else if (params instanceof ECGenParameterSpec)
            {
                // See if it's actually an OID string (SunJSSE ServerHandshaker setupEphemeralECDHKeys bug)
                domainParameters = getDomainParametersFromName(((ECGenParameterSpec)params).getName());
                if (domainParameters == null)
                {
                    throw new InvalidAlgorithmParameterException("unknown curve ID: " + ((ECGenParameterSpec)params).getName());
                }
            }
            else if (params == null)
            {
                domainParameters = CryptoServicesRegistrar.<ECDomainParameters>getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA);
                if (domainParameters == null)
                {
                    throw new InvalidAlgorithmParameterException("null AlgorithmParameterSpec passed but no implicit CA set");
                }
                domainParameters = new ECImplicitDomainParameters(domainParameters);
            }
            else
            {
                String name = getNameFrom(params);

                if (name != null)
                {
                    domainParameters = getDomainParametersFromName(name);
                    if (domainParameters == null)
                    {
                        throw new InvalidAlgorithmParameterException("unknown curve ID: " + name);
                    }
                }
                else
                {
                    throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
                }
            }

            if (algorithmType instanceof FipsAlgorithm)
            {
                if (parameters != null)
                {
                    if (parameters instanceof FipsEC.DSAParameters)
                    {
                        engine = new FipsEC.KeyPairGenerator(new FipsEC.KeyGenParameters((FipsEC.DSAParameters)parameters, domainParameters), random);
                    }
                    else if (parameters instanceof FipsEC.AgreementParameters)
                    {
                        engine = new FipsEC.KeyPairGenerator(new FipsEC.KeyGenParameters((FipsEC.AgreementParameters)parameters, domainParameters), random);
                    }
                    else
                    {
                        engine = new FipsEC.KeyPairGenerator(new FipsEC.KeyGenParameters((FipsEC.MQVAgreementParametersBuilder)parameters, domainParameters), random);
                    }
                }
                else
                {
                    engine = new FipsEC.KeyPairGenerator(new FipsEC.KeyGenParameters(domainParameters), random);
                }
            }
            else
            {
                if (parameters != null)
                {
                    engine = new EC.KeyPairGenerator(new EC.KeyGenParameters((EC.DSAParameters)parameters, domainParameters), random);
                }
                else
                {
                    engine = new EC.KeyPairGenerator(new EC.KeyGenParameters(domainParameters), random);
                }
            }

            initialised = true;
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                initialize(strength, fipsProvider.getDefaultSecureRandom());
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();

            AsymmetricECPublicKey pubKey = (AsymmetricECPublicKey)pair.getPublicKey();
            AsymmetricECPrivateKey privKey = (AsymmetricECPrivateKey)pair.getPrivateKey();

            return new KeyPair(new ProvECPublicKey(pubKey), new ProvECPrivateKey(privKey));
        }
    }

    private static ECDomainParameters getDomainParametersFromName(String curveName)
    {
        ECDomainParameters domainParameters;
        try
        {
            if (curveName.charAt(0) >= '0' && curveName.charAt(0) <= '2')
            {
                ASN1ObjectIdentifier oidID = new ASN1ObjectIdentifier(curveName);
                domainParameters = ECDomainParametersIndex.lookupDomainParameters(oidID);
            }
            else
            {
                if (curveName.indexOf(' ') > 0)
                {
                    curveName = curveName.substring(curveName.indexOf(' ') + 1);
                    domainParameters = getNamedECDomainParametersFromName(curveName);
                }
                else
                {
                    domainParameters = getNamedECDomainParametersFromName(curveName);
                }
            }
        }
        catch (IllegalArgumentException ex)
        {
            domainParameters = getNamedECDomainParametersFromName(curveName);
        }
        return domainParameters;
    }

    private static NamedECDomainParameters getNamedECDomainParametersFromName(final String curveName)
    {
        return ECDomainParametersIndex.lookupDomainParameters(new ECDomainParametersID()
        {
            public String getCurveName()
            {
                return curveName;
            }
        });
    }

    static String getNameFrom(final AlgorithmParameterSpec paramSpec)
    {
        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    Method m = paramSpec.getClass().getMethod("getName");

                    return m.invoke(paramSpec);
                }
                catch (Exception e)
                {
                    // ignore - maybe log?
                }

                return null;
            }
        });
    }

    private static class DhuParamsCreator
        implements ParametersCreator
    {
        private final boolean isTS;

        DhuParamsCreator(boolean isTS)
        {
            this.isTS = isTS;
        }

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            try
            {
                if (!(spec instanceof DHUParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("ECCDHU can only take an DHUParameterSpec");
                }

                DHUParameterSpec dhuSpec = (DHUParameterSpec)spec;

                if (isTS && !(dhuSpec.getKdfParameterSpec() instanceof TwoStepKDFParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("ECCDHU with TwoStep needs a TwoStepKDFParameterSpec");
                }

                if (dhuSpec.getEphemeralPublicKey() != null)
                {
                    return FipsEC.CDHU.using(publicKeyConverter.convertKey(FipsEC.CDHU.getAlgorithm(), dhuSpec.getEphemeralPublicKey()),
                        privateKeyConverter.convertKey(FipsEC.CDHU.getAlgorithm(), dhuSpec.getEphemeralPrivateKey()),
                        publicKeyConverter.convertKey(FipsEC.CDHU.getAlgorithm(), dhuSpec.getOtherPartyEphemeralKey()));
                }
                else
                {
                    return FipsEC.CDHU.using(
                        privateKeyConverter.convertKey(FipsEC.CDHU.getAlgorithm(), dhuSpec.getEphemeralPrivateKey()),
                        publicKeyConverter.convertKey(FipsEC.CDHU.getAlgorithm(), dhuSpec.getOtherPartyEphemeralKey()));
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidAlgorithmParameterException("Unable to convert keys in MQVParameterSpec: " + e.getMessage(), e);
            }
        }
    }

    private static class MqvParamsCreator
        implements ParametersCreator
    {
        private final boolean isTS;

        MqvParamsCreator(boolean isTS)
        {
            this.isTS = isTS;
        }

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            try
            {
                if (!(spec instanceof MQVParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("ECMQV can only take an MQVParameterSpec");
                }

                MQVParameterSpec mqvSpec = (MQVParameterSpec)spec;

                if (isTS && !(mqvSpec.getKdfParameterSpec() instanceof TwoStepKDFParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("ECMQV with TwoStep needs a TwoStepKDFParameterSpec");
                }

                if (mqvSpec.getEphemeralPublicKey() != null)
                {
                    return FipsEC.MQV.using(publicKeyConverter.convertKey(FipsEC.MQV.getAlgorithm(), mqvSpec.getEphemeralPublicKey()),
                        privateKeyConverter.convertKey(FipsEC.MQV.getAlgorithm(), mqvSpec.getEphemeralPrivateKey()),
                        publicKeyConverter.convertKey(FipsEC.MQV.getAlgorithm(), mqvSpec.getOtherPartyEphemeralKey()));
                }
                else
                {
                    return FipsEC.MQV.using(
                        privateKeyConverter.convertKey(FipsEC.MQV.getAlgorithm(), mqvSpec.getEphemeralPrivateKey()),
                        publicKeyConverter.convertKey(FipsEC.MQV.getAlgorithm(), mqvSpec.getOtherPartyEphemeralKey()));
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidAlgorithmParameterException("Unable to convert keys in MQVParameterSpec: " + e.getMessage(), e);
            }
        }
    }
}
