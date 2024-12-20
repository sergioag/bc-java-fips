package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for FIPS approved implementations of Deterministic Random Bit Generators (DRBGs) from SP 800-90A.
 */
public final class FipsDRBG
{
    // package protect constructor
    private FipsDRBG()
    {

    }

    private enum Variations
    {
        CTR_Triple_DES_168,
        CTR_AES_128,
        CTR_AES_192,
        CTR_AES_256
    }

    /**
     * HASH DRBG - SHA-1
     */
    public static final Base SHA1 = new Base(new FipsAlgorithm("SHA-1", FipsSHS.Variations.SHA1));

    /**
     * HASH DRBG - SHA-224
     */
    public static final Base SHA224 = new Base(new FipsAlgorithm("SHA-224", FipsSHS.Variations.SHA224));

    /**
     * HASH DRBG - SHA-256
     */
    public static final Base SHA256 = new Base(new FipsAlgorithm("SHA-256", FipsSHS.Variations.SHA256));

    /**
     * HASH DRBG - SHA-384
     */
    public static final Base SHA384 = new Base(new FipsAlgorithm("SHA-384", FipsSHS.Variations.SHA384));

    /**
     * HASH DRBG - SHA-512
     */
    public static final Base SHA512 = new Base(new FipsAlgorithm("SHA-512", FipsSHS.Variations.SHA512));

    /**
     * HASH DRBG - SHA-512/224
     */
    public static final Base SHA512_224 = new Base(new FipsAlgorithm("SHA-512(224)", FipsSHS.Variations.SHA512_224));

    /**
     * HASH DRBG - SHA-512/256
     */
    public static final Base SHA512_256 = new Base(new FipsAlgorithm("SHA-512(256)", FipsSHS.Variations.SHA512_256));

    /**
     * HMAC DRBG - SHA-1
     */
    public static final Base SHA1_HMAC = new Base(new FipsAlgorithm("SHA-1/HMAC", FipsSHS.Variations.SHA1_HMAC));

    /**
     * HMAC DRBG - SHA-224
     */
    public static final Base SHA224_HMAC = new Base(new FipsAlgorithm("SHA-224/HMAC", FipsSHS.Variations.SHA224_HMAC));

    /**
     * HMAC DRBG - SHA-256
     */
    public static final Base SHA256_HMAC = new Base(new FipsAlgorithm("SHA-256/HMAC", FipsSHS.Variations.SHA256_HMAC));

    /**
     * HMAC DRBG - SHA-384
     */
    public static final Base SHA384_HMAC = new Base(new FipsAlgorithm("SHA-384/HMAC", FipsSHS.Variations.SHA384_HMAC));

    /**
     * HMAC DRBG - SHA-512
     */
    public static final Base SHA512_HMAC = new Base(new FipsAlgorithm("SHA-512/HMAC", FipsSHS.Variations.SHA512_HMAC));

    /**
     * HMAC DRBG - SHA-512/224
     */
    public static final Base SHA512_224_HMAC = new Base(new FipsAlgorithm("SHA-512(224)/HMAC", FipsSHS.Variations.SHA512_224_HMAC));

    /**
     * HMAC DRBG - SHA-512/256
     */
    public static final Base SHA512_256_HMAC = new Base(new FipsAlgorithm("SHA-512(256)/HMAC", FipsSHS.Variations.SHA512_256_HMAC));

    /**
     * CTR DRBG - 3-Key TripleDES
     */
    public static final Base CTR_Triple_DES_168 = new Base(new FipsAlgorithm("TRIPLEDES", Variations.CTR_Triple_DES_168));

    /**
     * CTR DRBG - 128 bit AES
     */
    public static final Base CTR_AES_128 = new Base(new FipsAlgorithm("AES-128", Variations.CTR_AES_128));

    /**
     * CTR DRBG - 192 bit AES
     */
    public static final Base CTR_AES_192 = new Base(new FipsAlgorithm("AES-192", Variations.CTR_AES_192));

    /**
     * CTR DRBG - 256 bit AES
     */
    public static final Base CTR_AES_256 = new Base(new FipsAlgorithm("AES-256", Variations.CTR_AES_256));

    static
    {
        // FSM_STATE:5.DRBG.0, "DRBG KAT" ,"The module is performing DRBG KAT self-test"
        // FSM_TRANS:5.DRBG.0.1, "CONDITIONAL TEST", "DRBG KAT", "Invoke DRBG KAT self-test"
        drbgStartupTest();
        // FSM_TRANS:5.DRBG.0.2, "DRBG KAT", "POWER ON SELF-TEST", "DRBG KAT self-test successful completion"
        // FSM_TRANS:5.DRBG.0.3, "DRBG KAT", "SOFT ERROR", "DRBG KAT self-test failed"
    }

    public static class Base
        extends FipsParameters
    {
        Base(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }

        /**
         * Return a builder using an EntropySourceProvider based on the default SecureRandom with
         * predictionResistant set to false.
         * <p>
         * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
         * the default SecureRandom does for its generateSeed() call.
         * </p>
         * @return a new Builder instance.
         */
        public Builder fromDefaultEntropy()
        {
            SecureRandom entropySource = new SecureRandom();

            return new Builder(getAlgorithm(), entropySource, new BasicEntropySourceProvider(entropySource, false));
        }

        /**
         * Construct a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value
         * for prediction resistance.
         * <p>
         * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
         * the passed in SecureRandom does for its generateSeed() call.
         * </p>
         *
         * @param entropySource a source of entropy.
         * @param predictionResistant true if this entropySource is prediction resistant, false otherwise.
         * @return a new Builder instance.
         */
        public Builder fromEntropySource(SecureRandom entropySource, boolean predictionResistant)
        {
            return new Builder(getAlgorithm(), entropySource, new BasicEntropySourceProvider(entropySource, predictionResistant));
        }

        /**
         * Create a builder which makes creates the SecureRandom objects from a specified entropy source provider.
         * <p>
         * <b>Note:</b> If this method is used any calls to setSeed() in the resulting SecureRandom will be ignored.
         * </p>
         *
         * @param entropySourceProvider a provider of EntropySource objects.
         * @return a new Builder instance.
         */
        public Builder fromEntropySource(EntropySourceProvider entropySourceProvider)
        {
            return new Builder(getAlgorithm(), null, entropySourceProvider);
        }
    }

    /**
     * Builder for SecureRandom objects based on the FIPS DRBGs.
     */
    public static class Builder
    {
        private final FipsAlgorithm algorithm;
        private final SecureRandom random;
        private final EntropySourceProvider entropySourceProvider;

        private byte[] personalizationString;
        private int securityStrength = 256;
        private int entropyBitsRequired = 256;

        Builder(FipsAlgorithm algorithm, SecureRandom random, EntropySourceProvider entropySourceProvider)
        {
            FipsStatus.isReady();

            this.algorithm = algorithm;
            this.random = random;
            this.entropySourceProvider = entropySourceProvider;
        }

        /**
         * Set the personalization string for DRBG SecureRandoms created by this builder
         *
         * @param personalizationString the personalisation string for the underlying DRBG.
         * @return the current Builder instance.
         */
        public Builder setPersonalizationString(byte[] personalizationString)
        {
            this.personalizationString = Arrays.clone(personalizationString);

            return this;
        }

        /**
         * Set the security strength required for DRBGs used in building SecureRandom objects.
         *
         * @param securityStrength the security strength (in bits)
         * @return the current Builder instance.
         */
        public Builder setSecurityStrength(int securityStrength)
        {
            this.securityStrength = securityStrength;

            return this;
        }

        /**
         * Set the amount of entropy bits required for seeding and reseeding DRBGs used in building SecureRandom objects.
         *
         * @param entropyBitsRequired the number of bits of entropy to be requested from the entropy source on each seed/reseed.
         * @return the current Builder instance.
         */
        public Builder setEntropyBitsRequired(int entropyBitsRequired)
        {
            this.entropyBitsRequired = entropyBitsRequired;

            return this;
        }

        /**
         * Build a SecureRandom based on a SP 800-90A DRBG.
         *
         * @param nonce               nonce value to use in DRBG construction.
         * @param predictionResistant specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes.
         * @return a SecureRandom supported by a DRBG.
         */
        public FipsSecureRandom build(byte[] nonce, boolean predictionResistant)
        {
            return build(nonce, predictionResistant, null);
        }

        /**
         * Build a SecureRandom based on a SP 800-90A DRBG.
         *
         * @param nonce               nonce value to use in DRBG construction.
         * @param predictionResistant specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes.
         * @param additionalInput     initial additional input to be used for generating the initial continuous health check block by the DRBG.
         * @return a SecureRandom supported by a DRBG.
         */
        public FipsSecureRandom build(byte[] nonce, boolean predictionResistant, byte[] additionalInput)
        {
           return build(algorithm, nonce, predictionResistant, additionalInput);
        }

        private FipsSecureRandom build(FipsAlgorithm algorithm, byte[] nonce, boolean predictionResistant, byte[] additionalInput)
        {
            EntropySource entropySource = entropySourceProvider.get(entropyBitsRequired);
            if (algorithm.basicVariation() instanceof FipsSHS.Variations)
            {
                switch (((FipsSHS.Variations)algorithm.basicVariation()))
                {
                case SHA1:
                case SHA224:
                case SHA256:
                case SHA384:
                case SHA512:
                case SHA512_224:
                case SHA512_256:
                    HashDRBGProvider hashDRBGProvider = new HashDRBGProvider(algorithm, Arrays.clone(nonce), personalizationString, securityStrength, additionalInput);
                    return new FipsSecureRandom(random, hashDRBGProvider.getAlgorithmName(), new DRBGPseudoRandom(algorithm, entropySource, hashDRBGProvider), entropySource, predictionResistant);
                case SHA1_HMAC:
                case SHA224_HMAC:
                case SHA256_HMAC:
                case SHA384_HMAC:
                case SHA512_HMAC:
                case SHA512_224_HMAC:
                case SHA512_256_HMAC:
                    HMacDRBGProvider hMacDRBGProvider = new HMacDRBGProvider(algorithm, Arrays.clone(nonce), personalizationString, securityStrength, additionalInput);
                    return new FipsSecureRandom(random, hMacDRBGProvider.getAlgorithmName(), new DRBGPseudoRandom(algorithm, entropySource, hMacDRBGProvider), entropySource, predictionResistant);
                default:
                    throw new IllegalArgumentException("Unknown algorithm passed to build(): " + algorithm.getName());
                }
            }
            else
            {
                BlockCipher cipher;
                int keySizeInBits;

                switch (((Variations)algorithm.basicVariation()))
                {
                case CTR_AES_128:
                    cipher = FipsAES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 128;
                    break;
                case CTR_AES_192:
                    cipher = FipsAES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 192;
                    break;
                case CTR_AES_256:
                    cipher = FipsAES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 256;
                    break;
                case CTR_Triple_DES_168:
                    cipher = FipsTripleDES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 168;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown algorithm passed to build(): " + algorithm.getName());
                }

                CTRDRBGProvider ctrDRBGProvider = new CTRDRBGProvider(cipher, keySizeInBits, Arrays.clone(nonce), personalizationString, securityStrength, additionalInput);
                return new FipsSecureRandom(random, ctrDRBGProvider.getAlgorithmName(), new DRBGPseudoRandom(algorithm, entropySource, ctrDRBGProvider), entropySource, predictionResistant);
            }
        }
    }

    private static class HashDRBGProvider
        implements DRBGProvider
    {
        private final Digest digest;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;
        private final byte[] primaryAdditionalInput;

        public HashDRBGProvider(FipsAlgorithm algorithm, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
        {
            FipsStatus.isReady();
            this.digest = FipsSHS.createDigest(algorithm);
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
            this.primaryAdditionalInput = primaryAdditionalInput;
        }

        public DRBG get(EntropySource entropySource)
        {
            HashSP800DRBG drbg = new HashSP800DRBG(digest, securityStrength, entropySource, personalizationString, nonce);

            return new ContinuousTestingPseudoRNG(drbg, primaryAdditionalInput);
        }

        public String getAlgorithmName()
        {
            return "HASH-DRBG-" + getSimplifiedName(digest);
        }
    }

    private static class HMacDRBGProvider
        implements DRBGProvider
    {
        private final Mac hMac;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;
        private final byte[] primaryAdditionalInput;

        public HMacDRBGProvider(FipsAlgorithm algorithm, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
        {
            FipsStatus.isReady();
            this.hMac = FipsSHS.createHMac(algorithm);
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
            this.primaryAdditionalInput = primaryAdditionalInput;
        }

        public DRBG get(EntropySource entropySource)
        {
            HMacSP800DRBG drbg = new HMacSP800DRBG(hMac, securityStrength, entropySource, personalizationString, nonce);

            return new ContinuousTestingPseudoRNG(drbg, primaryAdditionalInput);
        }

        public String getAlgorithmName()
        {
            if (hMac instanceof HMac)
            {
                return "HMAC-DRBG-" + getSimplifiedName(((HMac)hMac).getUnderlyingDigest());
            }

            return "HMAC-DRBG-" + hMac.getAlgorithmName();
        }
    }

    private static class DRBGKey
    {
        private final Algorithm algorithm;
        private final Algorithm baseAlg;
        private final byte[] personalizationString;

        public DRBGKey(Algorithm algorithm, Algorithm baseAlg, byte[] personalizationString)
        {
            this.algorithm = algorithm;
            this.baseAlg = baseAlg;
            this.personalizationString = personalizationString;
        }

        public int hashCode()
        {
            return 7 * (algorithm.hashCode()
                + 7 * baseAlg.hashCode())
                + Arrays.hashCode(personalizationString);
        }

        public boolean equals(Object o)
        {
            DRBGKey other = (DRBGKey)o;

            return this.algorithm.equals(other.algorithm)
                && this.baseAlg.equals(baseAlg)
                && Arrays.areEqual(personalizationString, other.personalizationString);
        }
    }

    private static Map<DRBGKey, FipsSecureRandom> drbgMap = new ConcurrentHashMap<DRBGKey, FipsSecureRandom>();
    private static AtomicLong nonce = new AtomicLong(System.currentTimeMillis());

    /**
     * Return a basic DRBG created using the passed in Base and personalizationString with
     * a system defined nonce and configured with prediction resistance set to false.
     *
     * @param usage an algorithm object signifying the use of the DRBG.
     * @param drbgBase the base to construct the DRBG from.
     * @param personalizationString the personalizationString to use.
     * @return an appropriate FipsSecureRandom
     */
    public static FipsSecureRandom fetchBasicDRBG(Algorithm usage, Base drbgBase, byte[] personalizationString)
    {
        if (usage == null || drbgBase == null || personalizationString == null)
        {
            throw new NullPointerException("null parameter passed to fetchBasicDRBG()");
        }

        // in this case if we're still starting up isReady() will return false
        // if we're still booting - we return the constant boot up entropy provider
        if (!FipsStatus.isReady())
        {
            return drbgBase.fromEntropySource(new KATEntropyProvider())
                                    .build(null, false, personalizationString);
        }

        DRBGKey key = new DRBGKey(usage, drbgBase.getAlgorithm(), personalizationString);
        FipsSecureRandom drbg = drbgMap.get(key);
        if (drbg == null)
        {
            synchronized (usage)
            {
                drbg = drbgMap.get(key);
                if (drbg == null)
                {
                    drbg = drbgBase.fromEntropySource(new SecureRandom(), true)
                        .build(Pack.longToBigEndian(nonce.getAndIncrement()), false, personalizationString);
                    drbgMap.put(key, drbg);
                }
            }
        }

        return drbg;
    }

    private static class CTRDRBGProvider
        implements DRBGProvider
    {
        private final BlockCipher blockCipher;
        private final int keySizeInBits;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;
        private final byte[] primaryAdditionalInput;

        public CTRDRBGProvider(BlockCipher blockCipher, int keySizeInBits, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
        {
            FipsStatus.isReady();
            this.blockCipher = blockCipher;
            this.keySizeInBits = keySizeInBits;
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
            this.primaryAdditionalInput = primaryAdditionalInput;
        }

        public DRBG get(EntropySource entropySource)
        {
            CTRSP800DRBG drbg = new CTRSP800DRBG(blockCipher, keySizeInBits, securityStrength, entropySource, personalizationString, nonce);

            return new ContinuousTestingPseudoRNG(drbg, primaryAdditionalInput);
        }

        public String getAlgorithmName()
        {
            if (blockCipher instanceof DesEdeEngine)
            {
                return "CTR-DRBG-3KEY-TDES";
            }
            return "CTR-DRBG-" + blockCipher.getAlgorithmName() + keySizeInBits;
        }
    }

    private static String getSimplifiedName(Digest digest)
    {
        String name = digest.getAlgorithmName();

        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }

    private static void drbgStartupTest()
    {
        // IG 10.3.A - each algorithm, one PRF.
        SelfTestExecutor.validate(
            SHA256.getAlgorithm(), new DRBGHashSelfTest(SHA256.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "de1c6b0fe66e9106e5203fa821ead509dda22d703434d56a974eb94a47c90ca1e16479c239ab6097",
                            "05bfd156e55000ff68d9c71c6e9d240b385d3f0f52c8f2ba98f35a76104060cc7ee87083501eb159"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA256_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA256_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "2c332d2c6e24fb45d508614d5af3b1cc604b26c5674865557735b6a2900e39227cd467f0cb7ae0d8",
                            "1a3d5fce46b6b3aebe17b8f6421dfd7fa8dcd0429a749d6d3309f07ff31a742a68eb34bf4104f756"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            CTR_AES_128.getAlgorithm(), new DRBGCTRSelfTest(CTR_AES_128.getAlgorithm(),
                new DRBGTestVector(
                    FipsAES.ENGINE_PROVIDER.createEngine(),
                    128,
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    128,
                    new String[]
                        {
                            "8339142c7329b506b61514bdb8fd5ad225d72a564b1025000c33c43281ebbe1cddf0eace9493342e",
                            "b6a51deea6c2b019ab9d03ac730388c3af39d41f45c9263008dcf6e1d63dc8e9ad06624a4b5866ef"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
    }

    private abstract static class DRBGSelfTest
        extends VariantInternalKatTest
    {
        DRBGSelfTest(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    private static class DRBGHashSelfTest
        extends DRBGSelfTest
    {
        private final DRBGTestVector tv;

        DRBGHashSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv)
        {
            super(algorithm);
            this.tv = tv;
        }

        @Override
        void evaluate()
            throws Exception
        {
            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new HashSP800DRBG(tv.getDigest(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".1 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(0))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".2 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(1))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }
        }
    }

    private static class DRBGHMACSelfTest
        extends DRBGSelfTest
    {
        private final DRBGTestVector tv;

        DRBGHMACSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv)
        {
            super(algorithm);
            this.tv = tv;
        }

        @Override
        void evaluate()
            throws Exception
        {
            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new HMacSP800DRBG(new HMac(tv.getDigest()), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".1 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(0))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".2 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(1))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }
        }
    }

    private static class DRBGCTRSelfTest
        extends DRBGSelfTest
    {
        private final DRBGTestVector tv;

        DRBGCTRSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv)
        {
            super(algorithm);
            this.tv = tv;
        }

        @Override
        void evaluate()
            throws Exception
        {
            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new CTRSP800DRBG(tv.getCipher(), tv.keySizeInBits(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".1 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(0))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".2 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(1))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }
        }
    }

    private static class DRBGTestVector
    {
        private Digest _digest;
        private BlockCipher _cipher;
        private int _keySizeInBits;
        private EntropySource _eSource;
        private boolean _pr;
        private String _nonce;
        private String _personalisation;
        private int _ss;
        private String[] _ev;
        private List _ai = new ArrayList();

        public DRBGTestVector(Digest digest, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _digest = digest;
            _eSource = eSource;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = null;
        }

        public DRBGTestVector(BlockCipher cipher, int keySizeInBits, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _cipher = cipher;
            _keySizeInBits = keySizeInBits;
            _eSource = eSource;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = null;
        }

        public Digest getDigest()
        {
            return _digest;
        }

        public BlockCipher getCipher()
        {
            return _cipher;
        }

        public int keySizeInBits()
        {
            return _keySizeInBits;
        }

        public DRBGTestVector addAdditionalInput(String input)
        {
            _ai.add(input);

            return this;
        }

        public DRBGTestVector setPersonalizationString(String p)
        {
            _personalisation = p;

            return this;
        }

        public EntropySource entropySource()
        {
            return _eSource;
        }

        public boolean predictionResistance()
        {
            return _pr;
        }

        public byte[] nonce()
        {
            if (_nonce == null)
            {
                return null;
            }

            return Hex.decode(_nonce);
        }

        public byte[] personalizationString()
        {
            if (_personalisation == null)
            {
                return null;
            }

            return Hex.decode(_personalisation);
        }

        public int securityStrength()
        {
            return _ss;
        }

        public byte[] expectedValue(int index)
        {
            return Hex.decode(_ev[index]);
        }

        public byte[] additionalInput(int position)
        {
            int len = _ai.size();
            byte[] rv;
            if (position >= len)
            {
                rv = null;
            }
            else
            {
                rv = Hex.decode((String)(_ai.get(position)));
            }
            return rv;
        }
    }

    private static class KATEntropyProvider
        extends FixedEntropySourceProvider
    {
        KATEntropyProvider()
        {
            super(
                Hex.decode(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536"
                        + "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6"
                        + "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6"), true);
        }
    }
}
