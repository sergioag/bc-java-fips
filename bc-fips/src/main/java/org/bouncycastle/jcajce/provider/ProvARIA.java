package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.ARIA;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

class ProvARIA
    extends SymmetricAlgorithmProvider
{
    private ARIA.OperatorFactory operatorFactory;
    private ARIA.AEADOperatorFactory aeadOperatorFactory;
    private ARIA.KeyWrapOperatorFactory keyWrapOperatorFactory;

    ProvARIA()
    {

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            aeadOperatorFactory = new ARIA.AEADOperatorFactory();
            keyWrapOperatorFactory = new ARIA.KeyWrapOperatorFactory();
            operatorFactory = new ARIA.OperatorFactory();
        }
    }

    private static final String PREFIX = ProvARIA.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(ARIA.KW.getAlgorithm()) || parameters.getAlgorithm().equals(ARIA.KWP.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((ARIA.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
                        }

                        return parameters;
                    }
                };
            }
            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };

    private ARIA.OperatorFactory getGeneralOperatorFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        return operatorFactory;
    }

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("AlgorithmParameters.ARIA", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("ARIA");
            }
        }));
        provider.addAlias("AlgorithmParameters", "ARIA",
            NSRIObjectIdentifiers.id_aria128_cbc, NSRIObjectIdentifiers.id_aria192_cbc, NSRIObjectIdentifiers.id_aria256_cbc,
            NSRIObjectIdentifiers.id_aria128_cfb, NSRIObjectIdentifiers.id_aria192_cfb, NSRIObjectIdentifiers.id_aria256_cfb,
            NSRIObjectIdentifiers.id_aria128_ofb, NSRIObjectIdentifiers.id_aria192_ofb, NSRIObjectIdentifiers.id_aria256_ofb);

        provider.addAlias("AlgorithmParameters", "CCM",
            NSRIObjectIdentifiers.id_aria128_ccm, NSRIObjectIdentifiers.id_aria192_ccm, NSRIObjectIdentifiers.id_aria256_ccm);
        provider.addAlias("AlgorithmParameters", "GCM",
            NSRIObjectIdentifiers.id_aria128_gcm, NSRIObjectIdentifiers.id_aria192_gcm, NSRIObjectIdentifiers.id_aria256_gcm);
        
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", NSRIObjectIdentifiers.id_aria128_cbc, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "ARIA", 16);
            }
        }));
        provider.addAlias("AlgorithmParameterGenerator", NSRIObjectIdentifiers.id_aria128_cbc.getId(), NSRIObjectIdentifiers.id_aria192_cbc, NSRIObjectIdentifiers.id_aria256_cbc,
        NSRIObjectIdentifiers.id_aria128_cfb, NSRIObjectIdentifiers.id_aria192_cfb, NSRIObjectIdentifiers.id_aria256_cfb,
        NSRIObjectIdentifiers.id_aria128_ofb, NSRIObjectIdentifiers.id_aria192_ofb, NSRIObjectIdentifiers.id_aria256_ofb);

        provider.addAlias("AlgorithmParameterGenerator", "CCM",
            NSRIObjectIdentifiers.id_aria128_ccm, NSRIObjectIdentifiers.id_aria192_ccm, NSRIObjectIdentifiers.id_aria256_ccm);
        provider.addAlias("AlgorithmParameterGenerator", "GCM",
            NSRIObjectIdentifiers.id_aria128_gcm, NSRIObjectIdentifiers.id_aria192_gcm, NSRIObjectIdentifiers.id_aria256_gcm);

        provider.addAlgorithmImplementation("SecretKeyFactory.ARIA", PREFIX + "$ARIAKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("ARIA", ARIA.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size != 128 && size != 192 && size != 256)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for ARIA");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        GuardedEngineCreator aria128Fact = new GuardedEngineCreator(new EngineCreator()
        {
                public Object createInstance(Object constructorParameter)
                {
                    return createFixedFactory(128);
                }
        });
        addSecretKeyFactoryForOIDs(provider, PREFIX + "SKF", aria128Fact,
            NSRIObjectIdentifiers.id_aria128_ecb, NSRIObjectIdentifiers.id_aria128_cbc, NSRIObjectIdentifiers.id_aria128_cfb, NSRIObjectIdentifiers.id_aria128_ofb,
            NSRIObjectIdentifiers.id_aria128_gcm, NSRIObjectIdentifiers.id_aria128_ccm, NSRIObjectIdentifiers.id_aria128_kw, NSRIObjectIdentifiers.id_aria128_kwp);

        GuardedEngineCreator aria192Fact = new GuardedEngineCreator(new EngineCreator()
        {
                public Object createInstance(Object constructorParameter)
                {
                    return createFixedFactory(192);
                }
        });
        addSecretKeyFactoryForOIDs(provider, PREFIX + "SKF", aria192Fact,
            NSRIObjectIdentifiers.id_aria192_ecb, NSRIObjectIdentifiers.id_aria192_cbc, NSRIObjectIdentifiers.id_aria192_cfb, NSRIObjectIdentifiers.id_aria192_ofb,
            NSRIObjectIdentifiers.id_aria192_gcm, NSRIObjectIdentifiers.id_aria192_ccm, NSRIObjectIdentifiers.id_aria192_kw, NSRIObjectIdentifiers.id_aria192_kwp);

        GuardedEngineCreator aria256Fact = new GuardedEngineCreator(new EngineCreator()
        {
                public Object createInstance(Object constructorParameter)
                {
                    return createFixedFactory(256);
                }
        });
        addSecretKeyFactoryForOIDs(provider, PREFIX + "SKF", aria256Fact,
            NSRIObjectIdentifiers.id_aria256_ecb, NSRIObjectIdentifiers.id_aria256_cbc, NSRIObjectIdentifiers.id_aria256_cfb, NSRIObjectIdentifiers.id_aria256_ofb,
            NSRIObjectIdentifiers.id_aria256_gcm, NSRIObjectIdentifiers.id_aria256_ccm, NSRIObjectIdentifiers.id_aria256_kw, NSRIObjectIdentifiers.id_aria256_kwp);

        provider.addAlgorithmImplementation("Cipher.ARIA", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128,
                    ARIA.ECBwithPKCS7, ARIA.ECB, ARIA.ECBwithISO10126_2, ARIA.ECBwithISO7816_4, ARIA.ECBwithTBC, ARIA.ECBwithX923,
                    ARIA.CBC, ARIA.CBCwithPKCS7, ARIA.CBCwithISO10126_2, ARIA.CBCwithISO7816_4, ARIA.CBCwithTBC, ARIA.CBCwithX923,
                    ARIA.CBCwithCS1, ARIA.CBCwithCS2, ARIA.CBCwithCS3,
                    ARIA.CFB128, ARIA.CFB8, ARIA.OpenPGPCFB,
                    ARIA.OFB,
                    ARIA.CTR, ARIA.GCM, ARIA.CCM, ARIA.OCB, ARIA.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, getGeneralOperatorFactory(), aeadOperatorFactory)
                    .withParameters(cipherSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_ecb, PREFIX + "$ECB128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.ECBwithPKCS7)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_ecb, PREFIX + "$ECB192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.ECBwithPKCS7)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_ecb, PREFIX + "$ECB256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.ECBwithPKCS7)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_cbc, PREFIX + "$CBC128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CBCwithPKCS7)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_cbc, PREFIX + "$CBC192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CBCwithPKCS7)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_cbc, PREFIX + "$CBC256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CBCwithPKCS7)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_cfb, PREFIX + "$CFB128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CFB128)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_cfb, PREFIX + "$CFB192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CFB128)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_cfb, PREFIX + "$CFB256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CFB128)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_ofb, PREFIX + "$OFB128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.OFB)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_ofb, PREFIX + "$OFB192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.OFB)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_ofb, PREFIX + "$OFB256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.OFB)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_ccm, PREFIX + "$CCM128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CCM)
                        .withParameters(cipherSpecs)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_ccm, PREFIX + "$CCM192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CCM)
                        .withParameters(cipherSpecs)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_ccm, PREFIX + "$CCM256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.CCM)
                        .withParameters(cipherSpecs)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_gcm, PREFIX + "$gcm128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.GCM)
                        .withParameters(cipherSpecs)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_gcm, PREFIX + "$gcm192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.GCM)
                        .withParameters(cipherSpecs)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_gcm, PREFIX + "$gcm256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, ARIA.GCM)
                        .withParameters(cipherSpecs)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher.ARIAKW", PREFIX + "$Wrap", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KW).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_kw, PREFIX + "$Wrap128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KW).withFixedKeySize(128).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_kw, PREFIX + "$Wrap192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KW).withFixedKeySize(192).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_kw, PREFIX + "$Wrap256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KW).withFixedKeySize(256).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "ARIAKW", "ARIAWRAP");

        provider.addAlgorithmImplementation("Cipher.ARIAKWP",  PREFIX + "$WrapWithPad", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KWP).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_kwp, PREFIX + "$WrapPad128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KWP).withFixedKeySize(128).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_kwp, PREFIX + "$WrapPad192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KWP).withFixedKeySize(192).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_kwp, PREFIX + "$WrapPad256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, ARIA.KWP).withFixedKeySize(256).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "ARIAKWP", "ARIAWRAPPAD");

        provider.addAlgorithmImplementation("KeyGenerator.ARIA", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "ARIA", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new ARIA.KeyGenerator(keySize, random);
                    }
                });
            }
        }));

        GuardedEngineCreator aria128Gen = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "ARIA", 128, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new ARIA.KeyGenerator(128, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, aria128Gen,
            NSRIObjectIdentifiers.id_aria128_ecb, NSRIObjectIdentifiers.id_aria128_cbc, NSRIObjectIdentifiers.id_aria128_cfb, NSRIObjectIdentifiers.id_aria128_ofb,
            NSRIObjectIdentifiers.id_aria128_gcm, NSRIObjectIdentifiers.id_aria128_ccm, NSRIObjectIdentifiers.id_aria128_kw, NSRIObjectIdentifiers.id_aria128_kwp);

        GuardedEngineCreator aria192Gen = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "ARIA", 192, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new ARIA.KeyGenerator(192, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, aria192Gen,
            NSRIObjectIdentifiers.id_aria192_ecb, NSRIObjectIdentifiers.id_aria192_cbc, NSRIObjectIdentifiers.id_aria192_cfb, NSRIObjectIdentifiers.id_aria192_ofb,
            NSRIObjectIdentifiers.id_aria192_gcm, NSRIObjectIdentifiers.id_aria192_ccm, NSRIObjectIdentifiers.id_aria192_kw, NSRIObjectIdentifiers.id_aria192_kwp);

        GuardedEngineCreator aria256Gen = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "ARIA", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new ARIA.KeyGenerator(256, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, aria256Gen,
            NSRIObjectIdentifiers.id_aria256_ecb, NSRIObjectIdentifiers.id_aria256_cbc, NSRIObjectIdentifiers.id_aria256_cfb, NSRIObjectIdentifiers.id_aria256_ofb,
            NSRIObjectIdentifiers.id_aria256_gcm, NSRIObjectIdentifiers.id_aria256_ccm, NSRIObjectIdentifiers.id_aria256_kw, NSRIObjectIdentifiers.id_aria256_kwp);

        provider.addAlgorithmImplementation("Mac.ARIAGMAC", PREFIX + "$GMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(ARIA.GMAC, new ARIA.MACOperatorFactory(), new AuthParametersCreator(ARIA.GMAC));
            }
        }));
        provider.addAlias("Mac", "ARIAGMAC", "ARIA-GMAC");

        provider.addAlgorithmImplementation("Mac.ARIACMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(ARIA.CMAC, new ARIA.MACOperatorFactory(), new AuthParametersCreator(ARIA.CMAC));
            }
        }));
        provider.addAlias("Mac", "ARIACMAC", "ARIA-CMAC");

        provider.addAlgorithmImplementation("Mac.ARIACCMMAC", PREFIX + "$CAEMLLIACCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(ARIA.CCM, new ARIA.MACOperatorFactory(), new AuthParametersCreator(ARIA.CCM.withMACSize(128)));
            }
        }));
        provider.addAlias("Mac", "ARIACCMMAC", "ARIA-CCMMAC");

        provider.addAlgorithmImplementation("Mac", NSRIObjectIdentifiers.id_aria128_ccm, PREFIX + "$ARIA128CCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(ARIA.CCM, new ARIA.MACOperatorFactory(), new AuthParametersCreator(ARIA.CCM.withMACSize(128)), 128);
            }
        }));
        provider.addAlgorithmImplementation("Mac", NSRIObjectIdentifiers.id_aria192_ccm, PREFIX + "$ARIA192CCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(ARIA.CCM, new ARIA.MACOperatorFactory(), new AuthParametersCreator(ARIA.CCM.withMACSize(128)), 192);
            }
        }));
        provider.addAlgorithmImplementation("Mac", NSRIObjectIdentifiers.id_aria256_ccm, PREFIX + "$ARIA256CCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(ARIA.CCM, new ARIA.MACOperatorFactory(), new AuthParametersCreator(ARIA.CCM.withMACSize(128)), 256);
            }
        }));
    }

    private BaseSecretKeyFactory createFixedFactory(final int keySize)
    {
        return new BaseSecretKeyFactory("ARIA", ARIA.ALGORITHM, new BaseSecretKeyFactory.Validator()
        {
            public byte[] validated(byte[] keyBytes)
                throws InvalidKeySpecException
            {
                int size = keyBytes.length * 8;
                if (size != keySize)
                {
                    throw new InvalidKeySpecException("Provided key data wrong size for ARIA-" + keySize);
                }

                return keyBytes;
            }
        });
    }
}
