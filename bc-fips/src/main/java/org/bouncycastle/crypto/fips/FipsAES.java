package org.bouncycastle.crypto.fips;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.OperatorUsingSecureRandom;
import org.bouncycastle.crypto.OutputEncryptor;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.general.FipsRegister;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.MultiBlockCipher;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.fpe.SP80038G;
import org.bouncycastle.crypto.internal.io.CipherInputStream;
import org.bouncycastle.crypto.internal.io.CipherOutputStreamImpl;
import org.bouncycastle.crypto.internal.macs.AEADCipherMac;
import org.bouncycastle.crypto.internal.macs.CMac;
import org.bouncycastle.crypto.internal.macs.GMac;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.modes.CCMBlockCipher;
import org.bouncycastle.crypto.internal.modes.GCMBlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.internal.wrappers.SP80038FWrapEngine;
import org.bouncycastle.crypto.internal.wrappers.SP80038FWrapWithPaddingEngine;
import org.bouncycastle.crypto.util.RadixConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Source class for approved implementations of AES based algorithms
 */
public final class FipsAES
{
    private static final String FPE_DISABLED = "org.bouncycastle.fpe.disable";
    private static final String FF1_FPE_DISABLED = "org.bouncycastle.fpe.disable_ff1";

    private FipsAES()
    {

    }

    static final FipsEngineProvider<MultiBlockCipher> ENGINE_PROVIDER;

    /**
     * Raw AES algorithm, can be used for creating general purpose AES keys.
     */
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("AES");

    /**
     * AES in electronic code book (ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * AES in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * AES in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * AES in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * AES in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * AES in electronic code book mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * AES in cipher block chaining (CBC) mode.
     */
    public static final ParametersWithIV CBC = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * AES in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final ParametersWithIV CBCwithPKCS7 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * AES in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final ParametersWithIV CBCwithISO10126_2 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * AES in cipher block chaining mode with X9.23 padding.
     */
    public static final ParametersWithIV CBCwithX923 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * AES in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final ParametersWithIV CBCwithISO7816_4 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * AES in cipher block chaining mode with trailing bit complement (TBC) padding.
     */
    public static final ParametersWithIV CBCwithTBC = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * AES in cipher block chaining mode cipher text stealing type 1.
     */
    public static final ParametersWithIV CBCwithCS1 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * AES in cipher block chaining mode cipher text stealing type 2.
     */
    public static final ParametersWithIV CBCwithCS2 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * AES in cipher block chaining mode cipher text stealing type 3.
     */
    public static final ParametersWithIV CBCwithCS3 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * AES in cipher feedback (CFB) mode, 8 bit block size.
     */
    public static final ParametersWithIV CFB8 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * AES in cipher feedback (CFB) mode, 128 bit block size.
     */
    public static final ParametersWithIV CFB128 = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CFB128));

    /**
     * AES in output feedback (OFB) mode - 128 bit block size.
     */
    public static final ParametersWithIV OFB = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.OFB128));

    /**
     * AES in counter (CTR) mode.
     */
    public static final ParametersWithIV CTR = new ParametersWithIV(new FipsAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * AES in Galois/Counter Mode (GCM).
     */
    public static final AuthParameters GCM = new AuthParameters(new FipsAlgorithm(ALGORITHM, Mode.GCM));

    /**
     * AES in counter with CBC-MAC (CCM).
     */
    public static final AuthParameters CCM = new AuthParameters(new FipsAlgorithm(ALGORITHM, Mode.CCM));

    /**
     * AES cipher-based CMAC algorithm.
     */
    public static final AuthParameters CMAC = new AuthParameters(new FipsAlgorithm(ALGORITHM, Mode.CMAC));

    /**
     * AES cipher-based GMAC algorithm.
     */
    public static final AuthParameters GMAC = new AuthParameters(new FipsAlgorithm(ALGORITHM, Mode.GMAC));

    /**
     * AES as a FIPS SP800-38F/RFC 3394 key wrapper.
     */
    public static final WrapParameters KW = new WrapParameters(new FipsAlgorithm(ALGORITHM, Mode.WRAP));

    /**
     * AES as a FIPS SP800-38F key wrapper with padding.
     */
    public static final WrapParameters KWP = new WrapParameters(new FipsAlgorithm(ALGORITHM, Mode.WRAPPAD));

    /**
     * AES as in Format Preserving Encryption - FF1 mode.
     */
    public static final FPEParameters FF1 = new FPEParameters(new FipsAlgorithm(ALGORITHM, Mode.FF1));

    /**
     * AES as in Format Preserving Encryption - FF3 mode (now obsolete)
     */
//    public static final FPEParameters FF3 = new FPEParameters(new FipsAlgorithm(ALGORITHM, Mode.FF3));

    /**
     * AES as in Format Preserving Encryption - FF3-1 mode.
     */
    public static final FPEParameters FF3_1 = new FPEParameters(new FipsAlgorithm(ALGORITHM, Mode.FF3_1));

    static
    {
        EngineProvider provider = new EngineProvider();

        // FSM_STATE:5.AES.0,"AES ENCRYPT DECRYPT KAT","The module is performing AES encrypt and decrypt KAT self-test"
        // FSM_TRANS:5.AES.0.0,"CONDITIONAL TEST","AES ENCRYPT DECRYPT KAT","Invoke AES Encrypt/Decrypt KAT self-test"
        provider.createEngine();
        // FSM_TRANS:5.AES.0.1,"AES ENCRYPT DECRYPT KAT","CONDITIONAL TEST","AES Encrypt / Decrypt KAT self-test successful completion"
        // FSM_TRANS:5.AES.0.2,"AES ENCRYPT DECRYPT KAT","SOFT ERROR","AES Encrypt / Decrypt KAT self-test failed"

        // FSM_STATE:5.AES.1,"CCM GENERATE VERIFY KAT","The module is performing AES CCM generate and verify KAT self-test"
        // FSM_TRANS:5.AES.1.0,"CONDITIONAL TEST","CCM GENERATE VERIFY KAT","Invoke CCM Generate/Verify KAT self-test"
        ccmStartUpTest(provider);
        // FSM_TRANS:5.AES.1.1, "CCM GENERATE VERIFY KAT","CONDITIONAL TEST","CCM Generate/Verify KAT self-test successful completion"
        // FSM_TRANS:5.AES.1.2, "CCM GENERATE VERIFY KAT","SOFT ERROR","CCM Generate/Verify KAT self-test failed"

        // FSM_STATE:5.AES.2,"AES-CMAC GENERATE VERIFY KAT","The module is performing AES-CMAC generate and verify KAT self-test"
        // FSM_TRANS:5.AES.2.0,"CONDITIONAL TEST","AES-CMAC GENERATE VERIFY KAT","Invoke CMAC Generate/Verify KAT self-test"
        cmacStartUpTest(provider);
        // FSM_TRANS:5.AES.2.1,"AES-CMAC GENERATE VERIFY KAT", "CONDITIONAL TEST", "CMAC Generate/Verify KAT self-test successful completion"
        // FSM_TRANS:5.AES.2.2,"AES-CMAC GENERATE VERIFY KAT", "SOFT ERROR", "CMAC Generate/Verify KAT self-test failed"

        // FSM_STATE:5.AES.3,"GCM GMAC GENERATE VERIFY KAT","The module is performing GCM/GMAC generate and verify KAT self-test"
        // FSM_TRANS:5.AES.3.0,"CONDITIONAL TEST","GCM GMAC GENERATE VERIFY KAT","Invoke GCM Generate/Verify KAT self-test"
        gcmStartUpTest(provider);
        // FSM_TRANS:5.AES.3.1,"GCM GMAC GENERATE VERIFY KAT","CONDITIONAL TEST","GCM Generate/Verify KAT self-test successful completion"
        // FSM_TRANS:5.AES.3.2,"GCM GMAC GENERATE VERIFY KAT","SOFT ERROR","GCM Generate/Verify KAT self-test failed"

        ENGINE_PROVIDER = provider;

        FipsRegister.registerEngineProvider(ALGORITHM, provider);
    }

    /**
     * General AES operator parameters.
     */
    public static class Parameters
        extends FipsParameters
    {
        Parameters(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * General AES operator parameters with IV
     */
    public static final class ParametersWithIV
        extends Parameters
        implements org.bouncycastle.crypto.ParametersWithIV
    {
        private final byte[] iv;

        ParametersWithIV(FipsAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        private ParametersWithIV(FipsAlgorithm algorithm, byte[] iv)
        {
            super(algorithm);

            ((Mode)algorithm.basicVariation()).checkIv(iv, 16);

            this.iv = iv;
        }

        public ParametersWithIV withIV(byte[] iv)
        {
            return new ParametersWithIV(this.getAlgorithm(), Arrays.clone(iv));
        }

        public ParametersWithIV withIV(SecureRandom random)
        {
            return new ParametersWithIV(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(16, random));
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }
    }

    public static final class FPEParameters
        extends Parameters
    {
        private final RadixConverter radixConverter;
        private final byte[] tweak;
        private final boolean useInverse;

        FPEParameters(FipsAlgorithm algorithm)
        {
            this(algorithm, null, null, false);
        }

        private FPEParameters(FipsAlgorithm algorithm, RadixConverter radixConverter, byte[] tweak, boolean useInverse)
        {
            super(algorithm);

            this.radixConverter = radixConverter;
            this.tweak = tweak;
            this.useInverse = useInverse;
        }

        public int getRadix()
        {
            return radixConverter == null ? 0 : radixConverter.getRadix();
        }

        public byte[] getTweak()
        {
            return Arrays.clone(tweak);
        }

        public boolean isUsingInverseFunction()
        {
            return useInverse;
        }

        public FPEParameters withRadix(int radix)
        {
            return new FPEParameters(getAlgorithm(), new RadixConverter(radix), this.tweak, this.useInverse);
        }

        public FPEParameters withRadixConverter(RadixConverter radixConverter)
        {
            return new FPEParameters(getAlgorithm(), radixConverter, this.tweak, this.useInverse);
        }

        public FPEParameters withTweak(byte[] tweak)
        {
            return new FPEParameters(getAlgorithm(), this.radixConverter, Arrays.clone(tweak), this.useInverse);
        }

        public FPEParameters withUsingInverseFunction(boolean useInverse)
        {
            return new FPEParameters(getAlgorithm(), this.radixConverter, this.tweak, useInverse);
        }
    }

    /**
     * Parameters for AES key wrap operators.
     */
    public static final class WrapParameters
        extends FipsParameters
    {
        private final boolean useInverse;

        WrapParameters(FipsAlgorithm algorithm)
        {
            this(algorithm, false);
        }

        private WrapParameters(FipsAlgorithm algorithm, boolean useInverse)
        {
            super(algorithm);

            this.useInverse = useInverse;
        }

        public boolean isUsingInverseFunction()
        {
            return useInverse;
        }

        public WrapParameters withUsingInverseFunction(boolean useInverse)
        {
            return new WrapParameters(getAlgorithm(), useInverse);
        }
    }

    /**
     * Parameters for AES AEAD and MAC modes..
     */
    public static final class AuthParameters
        extends FipsParameters
        implements AuthenticationParametersWithIV
    {
        private final byte[] iv;
        private final int macLenInBits;

        /**
         * Base constructor - the algorithm, null IV.
         * In this case the tag length defaults to the 128 for GCM, CMAC, or GMAC, 64 bits otherwise.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(FipsAlgorithm algorithm)
        {
            this(algorithm, null, Utils.getDefaultMacSize(algorithm, 128));  // tag full blocksize or half
        }

        private AuthParameters(FipsAlgorithm algorithm, byte[] iv, int macLenInBits)
        {
            super(algorithm);

            this.iv = iv;
            this.macLenInBits = macLenInBits;
        }

        public int getMACSizeInBits()
        {
            return macLenInBits;
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }

        public AuthParameters withIV(byte[] iv)
        {
            return new AuthParameters(this.getAlgorithm(), Arrays.clone(iv), this.macLenInBits);
        }

        public AuthParameters withIV(SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (getAlgorithm().equals(GCM.getAlgorithm()))
                {
                    Utils.validateRandom(random, GCM.getAlgorithm(), "GCM IV can only be generated by an approved DRGB");
                }
            }
            if (getAlgorithm().equals(GCM.getAlgorithm()))
            {
                return new AuthParameters(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(12, random), this.macLenInBits);
            }
            else
            {
                return new AuthParameters(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(16, random), this.macLenInBits);
            }
        }

        /**
         * @param random source of randomness for iv (nonce)
         * @param ivLen  length of the iv (nonce) in bytes to use with the algorithm.
         */
        public AuthParameters withIV(SecureRandom random, int ivLen)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (getAlgorithm().equals(GCM.getAlgorithm()))
                {
                    Utils.validateRandom(random, GCM.getAlgorithm(), "GCM IV can only be generated by an approved DRGB");

                    if (ivLen < 12)
                    {
                        throw new FipsUnapprovedOperationError("GCM IV must be at least 96 bits", GCM.getAlgorithm());
                    }
                }
            }

            return new AuthParameters(this.getAlgorithm(), this.getAlgorithm().createIvIfNecessary(ivLen, random), this.macLenInBits);
        }

        /**
         * Return a new set of parameters specifying a specific mac size.
         *
         * @param macSizeInBits bit length of the MAC length.
         * @return a new set of AuthParameters for the MAC size.
         */
        public AuthParameters withMACSize(int macSizeInBits)
        {
            return new AuthParameters(this.getAlgorithm(), Arrays.clone(iv), macSizeInBits);
        }
    }

    /**
     * AES key generator.
     */
    public static final class KeyGenerator
        extends FipsSymmetricKeyGenerator<SymmetricSecretKey>
    {
        private final FipsAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        /**
         * Constructor to generate a general purpose AES key.
         *
         * @param keySizeInBits size of the key in bits.
         * @param random        secure random to use in key construction.
         */
        public KeyGenerator(int keySizeInBits, SecureRandom random)
        {
            this(ALGORITHM, keySizeInBits, random);
        }

        /**
         * Constructor to generate a specific purpose AES key for an algorithm in a particular parameter set.
         *
         * @param parameterSet  FIPS algorithm key is for,
         * @param keySizeInBits size of the key in bits.
         * @param random        secure random to use in key construction.
         */
        public KeyGenerator(FipsParameters parameterSet, int keySizeInBits, SecureRandom random)
        {
            this(parameterSet.getAlgorithm(), keySizeInBits, random);
        }

        private KeyGenerator(FipsAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateKeyGenRandom(random, keySizeInBits, algorithm);
            }

            if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256)
            {
                throw new IllegalArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.getName());
            }

            this.algorithm = algorithm;
            this.keySizeInBits = keySizeInBits;
            this.random = random;
        }

        /**
         * Generate a key,
         *
         * @return an AES key.
         */
        public SymmetricSecretKey generateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for basic AES encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends FipsSymmetricOperatorFactory<Parameters>
    {
        private final SecureRandom random;

        public OperatorFactory()
        {
            this(null);
        }

        private OperatorFactory(SecureRandom random)
        {
            this.random = random;
        }

        @Override
        public FipsOutputEncryptor<Parameters> createOutputEncryptor(final SymmetricKey key, final Parameters parameters)
        {
            final ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            if (parameters instanceof FPEParameters)
            {
                return new FpeOutProcessor(sKey, (FPEParameters)parameters, true);
            }
            return new OutEncryptor(sKey, parameters, null);
        }

        public FipsOutputEncryptor<Parameters> createOutputEncryptor(final SymmetricKey key, final FPEParameters parameters)
        {
            final ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            return new FpeOutProcessor(sKey, parameters, true);
        }


        @Override
        public FipsOutputDecryptor<Parameters> createOutputDecryptor(final SymmetricKey key, final Parameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            if (parameters instanceof FPEParameters)
            {
                return new FpeOutDecProcessor(sKey, (FPEParameters)parameters, false);
            }

            final BufferedBlockCipher cipher = BlockCipherUtils.createStandardCipher(false, sKey, ENGINE_PROVIDER, parameters, random);

            return new FipsOutputDecryptor<Parameters>()
            {

                @Override
                public Parameters getParameters()
                {
                    return parameters;
                }

                public int getMaxOutputSize(int inputLen)
                {
                    return cipher.getOutputSize(inputLen);
                }

                public int getUpdateOutputSize(int inputLen)
                {
                    return cipher.getUpdateOutputSize(inputLen);
                }

                @Override
                public CipherOutputStream getDecryptingStream(OutputStream out)
                {
                    if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                    {
                        return CipherOutputStreamImpl.getInstance(out, (StreamCipher)cipher.getUnderlyingCipher());
                    }

                    return CipherOutputStreamImpl.getInstance(out, cipher);
                }

                @Override
                public String toString()
                {
                    return "FipsOutputDecryptor(" + cipher.getUnderlyingCipher().toString() + ")";
                }
            };


        }

        @Override
        public FipsInputDecryptor<Parameters> createInputDecryptor(final SymmetricKey key, final Parameters parameters)
        {
            if (parameters instanceof FPEParameters)
            {
                return createInputDecryptor(key, (FPEParameters)parameters);
            }
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            final BufferedBlockCipher cipher = BlockCipherUtils.createStandardCipher(false, sKey, ENGINE_PROVIDER, parameters, random);

            return new FipsInputDecryptor<Parameters>()
            {
                @Override
                public Parameters getParameters()
                {
                    return parameters;
                }

                @Override
                public InputStream getDecryptingStream(InputStream in)
                {
                    if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                    {
                        return new CipherInputStream(in, (StreamCipher)cipher.getUnderlyingCipher());
                    }

                    return new CipherInputStream(in, cipher);
                }

                @Override
                public String toString()
                {
                    return "FipsInputDecryptor(" + cipher.getUnderlyingCipher().toString() + ")";
                }
            };
        }

        public FipsInputDecryptor<Parameters> createInputDecryptor(final SymmetricKey key, final FPEParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            final BlockCipher cipher = ENGINE_PROVIDER.createEngine();

            boolean isFF1 = FF1.getAlgorithm().equals(parameters.getAlgorithm());

            if (isFF1)
            {
                if (Properties.isOverrideSet(FPE_DISABLED) || Properties.isOverrideSet(FF1_FPE_DISABLED))
                {
                    throw new UnsupportedOperationException("FF1 encryption disabled");
                }
                cipher.init(!parameters.isUsingInverseFunction(), new KeyParameterImpl(sKey.getKeyBytes()));
            }
            else
            {
                if (Properties.isOverrideSet(FPE_DISABLED))
                {
                    throw new UnsupportedOperationException("FPE disabled");
                }
                cipher.init(!parameters.isUsingInverseFunction(), new KeyParameterImpl(Arrays.reverse(sKey.getKeyBytes())));
            }

            return new FipsInputDecryptor<Parameters>()
            {
                @Override
                public FPEParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public InputStream getDecryptingStream(InputStream in)
                {
                    return new LocalInputStream(cipher, parameters, in);
                }

                @Override
                public String toString()
                {
                    return "FipsInputDecryptor(" + cipher.toString() + ")";
                }
            };
        }

        private static class OutEncryptor
            extends FipsOutputEncryptor<Parameters>
            implements OperatorUsingSecureRandom<OutputEncryptor<Parameters>>
        {
            private final Parameters parameters;
            private final ValidatedSymmetricKey key;
            private final BufferedBlockCipher cipher;

            public OutEncryptor(ValidatedSymmetricKey key, Parameters parameters, SecureRandom random)
            {
                this.key = key;
                this.parameters = parameters;

                cipher = BlockCipherUtils.createStandardCipher(true, key, ENGINE_PROVIDER, parameters, random);
            }

            public CipherOutputStream getEncryptingStream(OutputStream out)
            {
                if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                {
                    return CipherOutputStreamImpl.getInstance(out, (StreamCipher)cipher.getUnderlyingCipher());
                }

                return CipherOutputStreamImpl.getInstance(out, cipher);
            }

            public OutputEncryptor<Parameters> withSecureRandom(SecureRandom random)
            {
                return new OutEncryptor(key, parameters, random);
            }

            public Parameters getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return cipher.getOutputSize(inputLen);
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return cipher.getUpdateOutputSize(inputLen);
            }

            @Override
            public String toString()
            {
                return "OutputEncryptor(" + cipher.toString() + ")";
            }
        }

        private class LocalInputStream
            extends InputStream
        {
            private final BlockCipher cipher;
            private final FPEParameters parameters;
            private final InputStream in;
            private final boolean isFF1;

            private volatile ByteArrayInputStream source;

            public LocalInputStream(BlockCipher cipher, FPEParameters parameters, InputStream in)
            {
                this.cipher = cipher;
                this.parameters = parameters;
                this.isFF1 = FF1.getAlgorithm().equals(parameters.getAlgorithm());
                this.in = in;
            }

            @Override
            public int read()
                throws IOException
            {
                if (source == null)
                {
                    byte[] data = Streams.readAll(in);

                    if (isFF1)
                    {
                        if (parameters.radixConverter.getRadix() > 256)
                        {
                            this.source = new ByteArrayInputStream(toByteArray(SP80038G.decryptFF1w(cipher, parameters.radixConverter, parameters.tweak, toShortArray(data, data.length), 0, data.length / 2)));
                        }
                        else
                        {
                            this.source = new ByteArrayInputStream(SP80038G.decryptFF1(cipher, parameters.radixConverter, parameters.tweak, data, 0, data.length));
                        }
                    }
                    else
                    {
                        if (parameters.radixConverter.getRadix() > 256)
                        {
                            this.source = new ByteArrayInputStream(toByteArray(SP80038G.decryptFF3_1w(cipher, parameters.radixConverter, parameters.tweak, toShortArray(data, data.length), 0, data.length / 2)));
                        }
                        else
                        {
                            this.source = new ByteArrayInputStream(SP80038G.decryptFF3_1(cipher, parameters.radixConverter, parameters.tweak, data, 0, data.length));
                        }
                    }
                }

                return source.read();
            }
        }

        private static class FpeOutProcessor
            extends FipsOutputEncryptor<Parameters>
        {
            private final FPEParameters parameters;
            private final BlockCipher cipher;
            private final OutputingStream localOutputStream;

            public FpeOutProcessor(ValidatedSymmetricKey key, FPEParameters parameters, boolean forEncryption)
            {
                this.parameters = parameters;

                cipher = ENGINE_PROVIDER.createEngine();

                boolean isFF1 = FF1.getAlgorithm().equals(parameters.getAlgorithm());

                if (isFF1)
                {
                    if (Properties.isOverrideSet(FPE_DISABLED) || Properties.isOverrideSet(FF1_FPE_DISABLED))
                    {
                        throw new UnsupportedOperationException("FF1 encryption disabled");
                    }
                    cipher.init(!parameters.isUsingInverseFunction(), new KeyParameterImpl(key.getKeyBytes()));
                }
                else
                {
                    if (Properties.isOverrideSet(FPE_DISABLED) || isApprovedMode())
                    {
                        throw new UnsupportedOperationException("FPE disabled");
                    }
                    cipher.init(!parameters.isUsingInverseFunction(), new KeyParameterImpl(Arrays.reverse(key.getKeyBytes())));
                }

                this.localOutputStream = forEncryption ? new EncryptingOutputStream(isFF1, cipher, parameters) : new DecryptingOutputStream(isFF1, cipher, parameters);
            }

            public CipherOutputStream getEncryptingStream(OutputStream out)
            {
                localOutputStream.init(out);

                return new CipherOutputStream()
                {
                    @Override
                    public void write(int b)
                        throws IOException
                    {
                        localOutputStream.write(b);
                    }

                    @Override
                    public void close()
                        throws IOException
                    {
                        localOutputStream.close();
                    }
                };
            }

            public FPEParameters getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return localOutputStream.size() + inputLen;
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return localOutputStream.size() + inputLen;
            }
        }

        private static class FpeOutDecProcessor
            extends FipsOutputDecryptor<Parameters>
        {
            private final FPEParameters parameters;
            private final BlockCipher cipher;
            private final OutputingStream localOutputStream;

            public FpeOutDecProcessor(ValidatedSymmetricKey key, FPEParameters parameters, boolean forEncryption)
            {
                this.parameters = parameters;

                cipher = ENGINE_PROVIDER.createEngine();

                boolean isFF1 = FF1.getAlgorithm().equals(parameters.getAlgorithm());

                if (isFF1)
                {
                    if (Properties.isOverrideSet(FPE_DISABLED) || Properties.isOverrideSet(FF1_FPE_DISABLED))
                    {
                        throw new UnsupportedOperationException("FF1 encryption disabled");
                    }
                    cipher.init(!parameters.isUsingInverseFunction(), new KeyParameterImpl(key.getKeyBytes()));
                }
                else
                {
                    if (Properties.isOverrideSet(FPE_DISABLED) || isApprovedMode())
                    {
                        throw new UnsupportedOperationException("FPE disabled");
                    }
                    cipher.init(!parameters.isUsingInverseFunction(), new KeyParameterImpl(Arrays.reverse(key.getKeyBytes())));
                }

                this.localOutputStream = forEncryption ? new EncryptingOutputStream(isFF1, cipher, parameters) : new DecryptingOutputStream(isFF1, cipher, parameters);
            }

            public CipherOutputStream getDecryptingStream(OutputStream out)
            {
                localOutputStream.init(out);

                return new CipherOutputStream()
                {
                    @Override
                    public void write(int b)
                        throws IOException
                    {
                        localOutputStream.write(b);
                    }

                    @Override
                    public void close()
                        throws IOException
                    {
                        localOutputStream.close();
                    }
                };
            }

            public FPEParameters getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return localOutputStream.size() + inputLen;
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return localOutputStream.size() + inputLen;
            }
        }

        private static interface OutputingStream
        {
            void init(OutputStream out);

            void write(int b)
                throws IOException;

            void close()
                throws IOException;

            int size();
        }

        private static class DecryptingOutputStream
            extends ErasableByteArrayOutputStream
            implements OutputingStream
        {
            private final boolean isFF1;
            private final BlockCipher cipher;
            private final FPEParameters parameters;
            private OutputStream output;

            DecryptingOutputStream(boolean isFF1, BlockCipher cipher, FPEParameters parameters)
            {
                this.isFF1 = isFF1;
                this.cipher = cipher;
                this.parameters = parameters;
            }

            public void init(OutputStream output)
            {
                this.output = output;
            }

            public void close()
                throws IOException
            {
                super.close();

                try
                {
                    if (isFF1)
                    {
                        if (parameters.radixConverter.getRadix() > 256)
                        {
                            output.write(FipsAES.toByteArray(SP80038G.decryptFF1w(cipher, parameters.radixConverter, parameters.getTweak(), toShortArray(this.buf, size()), 0, size() / 2)));
                        }
                        else
                        {
                            output.write(SP80038G.decryptFF1(cipher, parameters.radixConverter, parameters.getTweak(), this.buf, 0, size()));
                        }
                    }
                    else
                    {
                        if (parameters.radixConverter.getRadix() > 256)
                        {
                            output.write(FipsAES.toByteArray(SP80038G.decryptFF3_1w(cipher, parameters.radixConverter, parameters.getTweak(), toShortArray(buf, size()), 0, size() / 2)));
                        }
                        else
                        {
                            output.write(SP80038G.decryptFF3_1(cipher, parameters.radixConverter, parameters.getTweak(), buf, 0, size()));
                        }
                    }

                    output.flush();
                }
                catch (IllegalArgumentException e)
                {
                    throw new IOException(e.getMessage());
                }
                finally
                {
                    erase();
                }
            }
        }

        private static class EncryptingOutputStream
            extends ErasableByteArrayOutputStream
            implements OutputingStream
        {
            private final boolean isFF1;
            private final BlockCipher cipher;
            private final FPEParameters parameters;
            private OutputStream output;

            EncryptingOutputStream(boolean isFF1, BlockCipher cipher, FPEParameters parameters)
            {
                this.isFF1 = isFF1;
                this.cipher = cipher;
                this.parameters = parameters;
            }

            public void init(OutputStream output)
            {
                this.output = output;
            }

            public void close()
                throws IOException
            {
                super.close();

                try
                {
                    if (isFF1)
                    {
                        if (parameters.radixConverter.getRadix() > 256)
                        {
                            output.write(FipsAES.toByteArray(SP80038G.encryptFF1w(cipher, parameters.radixConverter, parameters.getTweak(), toShortArray(this.buf, size()), 0, size() / 2)));
                        }
                        else
                        {
                            output.write(SP80038G.encryptFF1(cipher, parameters.radixConverter, parameters.getTweak(), this.buf, 0, size()));
                        }
                    }
                    else
                    {
                        if (parameters.radixConverter.getRadix() > 256)
                        {
                            output.write(FipsAES.toByteArray(SP80038G.encryptFF3_1w(cipher, parameters.radixConverter, parameters.getTweak(), toShortArray(this.buf, size()), 0, size() / 2)));
                        }
                        else
                        {
                            output.write(SP80038G.encryptFF3_1(cipher, parameters.radixConverter, parameters.getTweak(), this.buf, 0, size()));
                        }
                    }

                    output.flush();
                }
                catch (IllegalArgumentException e)
                {
                    throw new IOException(e.getMessage());
                }
                finally
                {
                    erase();
                }
            }
        }
    }

    /**
     * Factory for producing FIPS AES MAC calculators.
     */
    public static final class MACOperatorFactory
        extends FipsMACOperatorFactory<AuthParameters>
    {
        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return makeMAC(parameters).getMacSize();
        }

        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            final Mac mac = makeMAC(parameters);

            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            if (parameters.getIV() != null)
            {
                mac.init(Utils.getParametersWithIV(sKey, parameters.getIV()));
            }
            else
            {
                mac.init(Utils.getKeyParameter(sKey));
            }

            return mac;
        }
    }

    static FipsEngineProvider<Mac> getMacProvider(final FipsAlgorithm algorithm)
    {
        final FipsEngineProvider<Mac> macProvider;

        switch (((Mode)algorithm.basicVariation()))
        {
        case CMAC:
            macProvider = new FipsEngineProvider<Mac>()
            {
                public Mac createEngine()
                {
                    return new CMac(ENGINE_PROVIDER.createEngine());
                }
            };
            break;
        case GMAC:
            macProvider = new FipsEngineProvider<Mac>()
            {
                public Mac createEngine()
                {
                    AEADBlockCipher gcm;
                    if (NativeLoader.hasNativeService(FipsNativeServices.AES_GCM))
                    {
                        gcm = AESNativeGCM.newInstance();
                    }
                    else
                    {
                        gcm = new GCMBlockCipher(ENGINE_PROVIDER.createEngine());
                    }
                    return new GMac(gcm);
                }
            };
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsAES MAC Provider: " + algorithm);
        }

        return macProvider;
    }

    static Mac makeMAC(final AuthParameters parameters)
    {
        final Mac mac;

        switch (((Mode)parameters.getAlgorithm().basicVariation()))
        {
        case CCM:
            mac = new AEADCipherMac(new CCMBlockCipher(ENGINE_PROVIDER.createEngine()), parameters.macLenInBits);
            break;
        case CMAC:
            mac = new CMac(ENGINE_PROVIDER.createEngine(), parameters.macLenInBits);
            break;
        case GMAC:
            AEADBlockCipher gcm;
            if (NativeLoader.hasNativeService(FipsNativeServices.AES_GCM))
            {
                gcm = AESNativeGCM.newInstance();
            }
            else
            {
                gcm = new GCMBlockCipher(ENGINE_PROVIDER.createEngine());
            }
            mac = new GMac(gcm, parameters.macLenInBits);
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsAES.OperatorFactory.createMACCalculator: " + parameters.getAlgorithm());
        }

        return mac;
    }

    /**
     * Factory for producing FIPS AES key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends FipsKeyWrapOperatorFactory<WrapParameters, SymmetricKey>
    {
        private Wrapper createWrapper(FipsAlgorithm algorithm, boolean useInverse)
        {
            Wrapper cipher;

            switch (((Mode)algorithm.basicVariation()))
            {
            case WRAP:
                cipher = new SP80038FWrapEngine(ENGINE_PROVIDER.createEngine(), useInverse);
                break;
            case WRAPPAD:
                cipher = new SP80038FWrapWithPaddingEngine(ENGINE_PROVIDER.createEngine(), useInverse);
                break;
            default:
                throw new IllegalArgumentException("Unknown algorithm passed to FipsAES.KeyWrapOperatorFactory: " + algorithm.getName());
            }

            return cipher;
        }

        @Override
        public FipsKeyWrapper<WrapParameters> createKeyWrapper(SymmetricKey key, final WrapParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            final Wrapper wrapper = createWrapper(parameters.getAlgorithm(), parameters.useInverse);

            wrapper.init(true, Utils.getKeyParameter(sKey));

            return new FipsKeyWrapper<WrapParameters>()
            {
                public WrapParameters getParameters()
                {
                    return parameters;
                }

                public byte[] wrap(byte[] in, int inOff, int inLen)
                    throws PlainInputProcessingException
                {
                    try
                    {
                        return wrapper.wrap(in, inOff, inLen);
                    }
                    catch (Exception e)
                    {
                        throw new PlainInputProcessingException("Unable to wrap key: " + e.getMessage(), e);
                    }
                }
            };
        }

        @Override
        public FipsKeyUnwrapper<WrapParameters> createKeyUnwrapper(SymmetricKey key, final WrapParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());

            final Wrapper wrapper = createWrapper(parameters.getAlgorithm(), parameters.useInverse);

            wrapper.init(false, Utils.getKeyParameter(sKey));

            return new FipsKeyUnwrapper<WrapParameters>()
            {
                public WrapParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] unwrap(byte[] in, int inOff, int inLen)
                    throws InvalidWrappingException
                {
                    try
                    {
                        return wrapper.unwrap(in, inOff, inLen);
                    }
                    catch (InvalidCipherTextException e)
                    {
                        throw new InvalidWrappingException("Unable to unwrap key: " + e.getMessage(), e);
                    }
                }
            };
        }
    }

    /**
     * Factory for AEAD encryption/decryption operations.
     */
    public static final class AEADOperatorFactory
        extends FipsAEADOperatorFactory<AuthParameters>
    {
        @Override
        public FipsOutputAEADEncryptor<AuthParameters> createOutputAEADEncryptor(SymmetricKey key, final AuthParameters parameter)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameter.getAlgorithm());

            return new OutEncryptor(sKey, parameter);
        }

        @Override
        public FipsOutputAEADDecryptor<AuthParameters> createOutputAEADDecryptor(SymmetricKey key, final AuthParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());
            final AEADBlockCipher cipher = BlockCipherUtils.createAEADCipher(parameters.getAlgorithm(), ENGINE_PROVIDER);

            if (parameters.iv != null)
            {
                cipher.init(false, Utils.getAEADParameters(sKey, parameters.iv, parameters.macLenInBits));
            }
            else
            {
                throw new IllegalArgumentException("AEAD decryption requires an iv/nonce to be provided.");
            }

            return new FipsOutputAEADDecryptor<AuthParameters>()
            {
                @Override
                public AuthParameters getParameters()
                {
                    return parameters;
                }

                public int getMaxOutputSize(int inputLen)
                {
                    return cipher.getOutputSize(inputLen);
                }

                public int getUpdateOutputSize(int inputLen)
                {
                    return cipher.getUpdateOutputSize(inputLen);
                }

                @Override
                public UpdateOutputStream getAADStream()
                {
                    return new AADStream(cipher);
                }

                @Override
                public CipherOutputStream getDecryptingStream(final OutputStream out)
                {
                    return CipherOutputStreamImpl.getInstance(out, cipher);
                }

                @Override
                public byte[] getMAC()
                {
                    return cipher.getMac();
                }

                public String toString()
                {
                    return "FipsOutputAEADDecryptor(" + cipher.toString() + ")";
                }

            };
        }

        @Override
        public FipsInputAEADDecryptor<AuthParameters> createInputAEADDecryptor(SymmetricKey key, final AuthParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters.getAlgorithm());
            final AEADBlockCipher cipher = BlockCipherUtils.createAEADCipher(parameters.getAlgorithm(), ENGINE_PROVIDER);

            if (parameters.iv != null)
            {
                cipher.init(false, Utils.getAEADParameters(sKey, parameters.iv, parameters.macLenInBits));
            }
            else
            {
                throw new IllegalArgumentException("AEAD decryption requires an iv/nonce to be provided.");
            }

            return new FipsInputAEADDecryptor<AuthParameters>()
            {
                @Override
                public AuthParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public UpdateOutputStream getAADStream()
                {
                    return new AADStream(cipher);
                }

                @Override
                public InputStream getDecryptingStream(InputStream in)
                {
                    return new CipherInputStream(in, cipher);
                }

                @Override
                public byte[] getMAC()
                {
                    return cipher.getMac();
                }
            };
        }

        private static class OutEncryptor
            extends FipsOutputAEADEncryptor<AuthParameters>
        {
            private final AuthParameters parameters;
            private final AEADBlockCipher cipher;

            public OutEncryptor(ValidatedSymmetricKey key, AuthParameters parameters)
            {
                this.parameters = parameters;
                this.cipher = BlockCipherUtils.createAEADCipher(parameters.getAlgorithm(), ENGINE_PROVIDER);

                if (parameters.iv != null)
                {
                    cipher.init(true, Utils.getAEADParameters(key, parameters.iv, parameters.macLenInBits));
                }
                else
                {
                    throw new IllegalArgumentException("AEAD encryption requires an iv/nonce to be provided.");
                }
            }

            public AuthParameters getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return cipher.getOutputSize(inputLen);
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return cipher.getUpdateOutputSize(inputLen);
            }

            @Override
            public UpdateOutputStream getAADStream()
            {
                return new AADStream(cipher);
            }

            @Override
            public CipherOutputStream getEncryptingStream(final OutputStream out)
            {
                return CipherOutputStreamImpl.getInstance(out, cipher);
            }

            @Override
            public byte[] getMAC()
            {
                return cipher.getMac();
            }

            @Override
            public String toString()
            {
                return "OutEncryptor(" + cipher.toString() + ")";
            }

        }

        private static class AADStream
            extends UpdateOutputStream
        {
            private AEADBlockCipher cipher;

            public AADStream(AEADBlockCipher cipher)
            {
                this.cipher = cipher;
            }

            @Override
            public void write(byte[] buf, int off, int len)
                throws IOException
            {
                cipher.processAADBytes(buf, off, len);
            }

            @Override
            public void write(int b)
                throws IOException
            {
                cipher.processAADByte((byte)b);
            }
        }
    }

    private static short[] toShortArray(byte[] buf, int length)
    {
        if ((length & 1) != 0)
        {
            throw new IllegalArgumentException("data must be an even number of bytes for a wide radix");
        }

        short[] rv = new short[length / 2];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Pack.bigEndianToShort(buf, i * 2);
        }

        return rv;
    }

    private static byte[] toByteArray(short[] buf)
    {
        byte[] rv = new byte[buf.length * 2];

        for (int i = 0; i != buf.length; i++)
        {
            Pack.shortToBigEndian(buf[i], rv, i * 2);
        }

        return rv;
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, FipsAlgorithm fipsAlgorithm)
    {
        // FSM_STATE:5.AES.4,"AES KEY VALIDITY TEST", "The module is validating the size and purpose of an AES key"
        // FSM_TRANS:5.AES.4.0,"CONDITIONAL TEST", "AES KEY VALIDITY TEST", "Invoke Validity test on AES key"
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (keyLength != 128 && keyLength != 192 && keyLength != 256)
        {
            // FSM_TRANS:5.AES.4.2,"AES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on AES key failed"
            throw new IllegalKeyException("AES key must be of length 128, 192, or 256");
        }

        Algorithm algorithm = vKey.getAlgorithm();

        if (!algorithm.equals(ALGORITHM))
        {
            if (!algorithm.equals(fipsAlgorithm))
            {
                // FSM_TRANS:5.AES.4.2,"AES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on AES key failed"
                throw new IllegalKeyException("FIPS Key not for specified algorithm");
            }
        }

        // FSM_TRANS:5.AES.4.1,"AES KEY VALIDITY TEST", "CONDITIONAL TEST", "Validity test on AES key successful"
        return vKey;
    }

    private static final class EngineProvider
        extends FipsEngineProvider<MultiBlockCipher>
    {
        private static final byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
        private static final byte[] output = Hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a");

        private static final byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        public MultiBlockCipher createEngine()
        {
            if (NativeLoader.hasNativeService(FipsNativeServices.AES_ECB))
            {
                return SelfTestExecutor.validate(ALGORITHM, new AESNativeEngine(), new VariantKatTest<AESNativeEngine>()
                {
                    public void evaluate(AESNativeEngine aesEngine)
                    {

                        byte[] tmp = new byte[input.length];

                        KeyParameter key = new KeyParameterImpl(keyBytes);

                        aesEngine.init(true, key);

                        aesEngine.processBlock(input, 0, tmp, 0);

                        if (!Arrays.areEqual(output, tmp))
                        {
                            fail("Failed self test on encryption");
                        }

                        aesEngine.init(false, key);

                        aesEngine.processBlock(tmp, 0, tmp, 0);

                        if (!Arrays.areEqual(input, tmp))
                        {
                            fail("Failed self test on decryption");
                        }
                    }
                });
            }

            return SelfTestExecutor.validate(ALGORITHM, new AESEngine(), new VariantKatTest<AESEngine>()
            {
                public void evaluate(AESEngine aesEngine)
                {

                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(keyBytes);

                    aesEngine.init(true, key);

                    aesEngine.processBlock(input, 0, tmp, 0);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    aesEngine.init(false, key);

                    aesEngine.processBlock(tmp, 0, tmp, 0);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }

    private static void ccmStartUpTest(EngineProvider provider)
    {
        SelfTestExecutor.validate(CCM.getAlgorithm(), provider, new VariantKatTest<EngineProvider>()
        {
            public void evaluate(EngineProvider provider)
                throws Exception
            {
                byte[] K = Hex.decode("404142434445464748494a4b4c4d4e4f");
                byte[] N = Hex.decode("10111213141516");
                byte[] A = Hex.decode("0001020304050607");
                byte[] P = Hex.decode("20212223");
                byte[] C = Hex.decode("7162015b4dac255d");
                byte[] T = Hex.decode("6084341b");

                BlockCipher aesCipher = provider.createEngine();
                CCMBlockCipher encCipher = new CCMBlockCipher(aesCipher);

                int macSize = T.length * 8;

                KeyParameter keyParam = new KeyParameterImpl(K);

                encCipher.init(true, new org.bouncycastle.crypto.internal.params.AEADParameters(keyParam, macSize, N, A));

                byte[] enc = new byte[C.length];

                int len = encCipher.processBytes(P, 0, P.length, enc, 0);

                encCipher.doFinal(enc, len);

                if (!Arrays.areEqual(C, enc))
                {
                    fail("Encrypted stream fails to match in self test");
                }

                if (!Arrays.areEqual(T, encCipher.getMac()))
                {
                    fail("MAC fails to match in self test encrypt");
                }

                CCMBlockCipher decCipher = new CCMBlockCipher(aesCipher);

                decCipher.init(false, new org.bouncycastle.crypto.internal.params.AEADParameters(keyParam, macSize, N, A));

                byte[] tmp = new byte[enc.length];

                len = decCipher.processBytes(enc, 0, enc.length, tmp, 0);

                len += decCipher.doFinal(tmp, len);

                byte[] dec = new byte[len];

                System.arraycopy(tmp, 0, dec, 0, len);

                if (!Arrays.areEqual(P, dec))
                {
                    fail("Decrypted stream fails to match in self test");
                }

                if (!Arrays.areEqual(T, decCipher.getMac()))
                {
                    fail("MAC fails to match in self test");
                }
            }
        });
    }

    private static void cmacStartUpTest(final EngineProvider provider)
    {
        SelfTestExecutor.validate(CMAC.getAlgorithm(), provider, new BasicKatTest<EngineProvider>()
        {
            public boolean hasTestPassed(EngineProvider engine)
            {
                byte[] keyBytes128 = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
                byte[] input16 = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
                byte[] output_k128_m16 = Hex.decode("070a16b46b4d4144f79bdd9dd04a287c");

                Mac mac = new CMac(provider.createEngine(), 128);

                //128 bytes key

                KeyParameter key = new KeyParameterImpl(keyBytes128);

                // 0 bytes message - 128 bytes key
                mac.init(key);

                mac.update(input16, 0, input16.length);

                byte[] out = new byte[16];

                mac.doFinal(out, 0);

                return Arrays.areEqual(out, output_k128_m16);
            }
        });
    }

    private static void gcmStartUpTest(EngineProvider provider)
    {
        if (NativeLoader.hasNativeService(FipsNativeServices.AES_GCM))
        {
            // newInstance will launch the startup test.
            AESNativeGCM.newInstance();
        }
        else
        {
            SelfTestExecutor.validate(GCM.getAlgorithm(), provider, new VariantKatTest<EngineProvider>()
            {
                public void evaluate(EngineProvider provider)
                    throws Exception
                {
                    AEADBlockCipher encCipher;
                    BlockCipher aesCipher = provider.createEngine();
                    encCipher = new GCMBlockCipher(aesCipher);

                    byte[] K = Hex.decode("feffe9928665731c6d6a8f9467308308");
                    byte[] P = Hex.decode("d9313225f88406e5a55909c5aff5269a"
                        + "86a7a9531534f7da2e4c303d8a318a72"
                        + "1c3c0c95956809532fcf0e2449a6b525"
                        + "b16aedf5aa0de657ba637b39");
                    byte[] A = Hex.decode("feedfacedeadbeeffeedfacedeadbeef"
                        + "abaddad2");
                    byte[] IV = Hex.decode("cafebabefacedbaddecaf888");
                    byte[] C = Hex.decode("42831ec2217774244b7221b784d0d49c"
                        + "e3aa212f2c02a4e035c17e2329aca12e"
                        + "21d514b25466931c7d8f6a5aac84aa05"
                        + "1ba30b396a0aac973d58e091");
                    byte[] T = Hex.decode("5bc94fbc3221a5db94fae95ae7121a47");

                    CipherParameters params = new org.bouncycastle.crypto.internal.params.AEADParameters(new KeyParameterImpl(K), T.length * 8, IV, A);

                    encCipher.init(true, params);

                    byte[] enc = new byte[encCipher.getOutputSize(P.length)];

                    int len = encCipher.processBytes(P, 0, P.length, enc, 0);
                    len += encCipher.doFinal(enc, len);

                    if (enc.length != len)
                    {
                        fail("Encryption reported incorrect length");
                    }

                    byte[] mac = encCipher.getMac();

                    byte[] data = new byte[P.length];
                    System.arraycopy(enc, 0, data, 0, data.length);
                    byte[] tail = new byte[enc.length - P.length];
                    System.arraycopy(enc, P.length, tail, 0, tail.length);

                    if (!Arrays.areEqual(C, data))
                    {
                        fail("Incorrect encrypt");
                    }

                    if (!Arrays.areEqual(T, mac))
                    {
                        fail("getMac() returned wrong MAC");
                    }

                    if (!Arrays.areEqual(T, tail))
                    {
                        fail("Stream contained wrong MAC");
                    }

                    GCMBlockCipher decCipher = new GCMBlockCipher(aesCipher);

                    decCipher.init(false, params);

                    byte[] dec = new byte[decCipher.getOutputSize(enc.length)];

                    len = decCipher.processBytes(enc, 0, enc.length, dec, 0);
                    decCipher.doFinal(dec, len);
                    mac = decCipher.getMac();

                    data = new byte[C.length];
                    System.arraycopy(dec, 0, data, 0, data.length);

                    if (!Arrays.areEqual(P, data))
                    {
                        fail("Incorrect decrypt");
                    }

                    if (!Arrays.areEqual(T, mac))
                    {
                        fail("Incorrect MAC on decrypt");
                    }
                }
            });
        }
    }

    private static class ErasableByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        public void erase()
        {
            Arrays.clear(buf);
            this.reset();
        }
    }

    private static boolean isApprovedMode()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("FF3-1 not supported in approved-only mode");
        }

        return false;
    }
}
