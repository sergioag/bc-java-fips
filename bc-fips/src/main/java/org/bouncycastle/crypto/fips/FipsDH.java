package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.asymmetric.DHDomainParametersID;
import org.bouncycastle.crypto.asymmetric.DHDomainParametersIndex;
import org.bouncycastle.crypto.asymmetric.DHValidationParameters;
import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.asymmetric.DSAValidationParameters;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.PrimeCertaintyCalculator;
import org.bouncycastle.crypto.internal.params.DhKeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DhParameters;
import org.bouncycastle.crypto.internal.params.DhPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DhPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.DhuPrivateParameters;
import org.bouncycastle.crypto.internal.params.DhuPublicParameters;
import org.bouncycastle.crypto.internal.params.MqvPrivateParameters;
import org.bouncycastle.crypto.internal.params.MqvPublicParameters;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for FIPS approved mode Diffie-Hellman implementations.
 */
public final class FipsDH
{
    private static final int MIN_FIPS_KEY_STRENGTH = 2048;       // 112 bits of security

    static final FipsEngineProvider<DhBasicAgreement> AGREEMENT_PROVIDER;
    static final FipsEngineProvider<MqvBasicAgreement> MQV_PROVIDER;
    static final FipsEngineProvider<DhuBasicAgreement> DHU_PROVIDER;

    private enum Variations
    {
        DH,
        MQV,
        DHU
    }

    /**
     * Basic Diffie-Hellman key marker, can be used for creating general purpose Diffie-Hellman keys.
     */
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("DH");

    private static final FipsAlgorithm ALGORITHM_DH = new FipsAlgorithm("DH", Variations.DH);
    private static final FipsAlgorithm ALGORITHM_MQV = new FipsAlgorithm("DH", Variations.MQV);
    private static final FipsAlgorithm ALGORITHM_DHU = new FipsAlgorithm("DH", Variations.DHU);

    /**
     * Regular Diffie-Hellman algorithm marker.
     */
    public static final AgreementParameters DH = new AgreementParameters();
    /**
     * Regular MQV algorithm marker.
     */
    public static final MQVAgreementParametersBuilder MQV = new MQVAgreementParametersBuilder();

    /**
     * Unified Diffie-Hellman algorithm marker.
     */
    public static final DHUAgreementParametersBuilder DHU = new DHUAgreementParametersBuilder();

    /**
     * An enumeration of DHDomainParametersID for some pre-defined DH parameter sets.
     */
    public enum DomainParameterID
        implements DHDomainParametersID
    {
        ffdhe2048("ffdhe2048"),
        ffdhe3072("ffdhe3072"),
        ffdhe4096("ffdhe4096"),
        ffdhe6144("ffdhe6144"),
        ffdhe8192("ffdhe8192"),
        modp2048("modp2048"),
        modp3072("modp3072"),
        modp4096("modp4096"),
        modp6144("modp6144"),
        modp8192("modp8192");

        private final String name;

        DomainParameterID(String name)
        {
            this.name = name;
        }

        public String getName()
        {
            return name;
        }
    }

    static
    {
        // FSM_STATE:5.DH.0,"KAS CVL Primitive 'Z' computation KAT", "The module is performing KAS CVL Primitive 'Z' computation KAT verify KAT self-test"
        // FSM_TRANS:5.DH.0.0,"CONDITIONAL TEST", "KAS CVL Primitive 'Z' computation KAT", "Invoke KAS CVL Primitive 'Z' computation KAT self-test"
        ffPrimitiveZTest();
        // FSM_TRANS:5.DH.0.1,"KAS CVL Primitive 'Z' computation KAT", "CONDITIONAL TEST", "KAS CVL Primitive 'Z' computation KAT self-test successful completion"
        // FSM_TRANS:5.DH.0.2,"KAS CVL Primitive 'Z' computation KAT", "SOFT ERROR", "KAS CVL Primitive 'Z' computation KAT self-test failed"

        AGREEMENT_PROVIDER = new AgreementProvider();
        MQV_PROVIDER = new MqvProvider();
        DHU_PROVIDER = new DhuProvider();

        // FSM_STATE:5.DH.1,"FF AGREEMENT KAT", "The module is performing FF Key Agreement verify KAT self-test"
        // FSM_TRANS:5.DH.1.0,"CONDITIONAL TEST", "FF AGREEMENT KAT", "Invoke FF Diffie-Hellman/MQV  KAT self-test"
        AGREEMENT_PROVIDER.createEngine();
        MQV_PROVIDER.createEngine();
        DHU_PROVIDER.createEngine();
        // FSM_TRANS:5.DH.1.1,"FF AGREEMENT KAT", "CONDITIONAL TEST", "FF Diffie-Hellman/MQV KAT self-test successful completion"
        // FSM_TRANS:5.DH.1.2,"FF AGREEMENT KAT", "SOFT ERROR", "FF Diffie-Hellman/MQV KAT self-test failed"
    }

    private FipsDH()
    {

    }

    /**
     * Parameters for Diffie-Hellman key pair generation.
     */
    public static final class KeyGenParameters
        extends FipsParameters
    {
        private final DHDomainParameters domainParameters;

        /**
         * Constructor for the default algorithm ID.
         *
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(DHDomainParameters domainParameters)
        {
            this(ALGORITHM, domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID from a parameter set.
         *
         * @param parameters       the parameters containing the algorithm the generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(AgreementParameters parameters, DHDomainParameters domainParameters)
        {
            this(parameters.getAlgorithm(), domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID from an MQV builder.
         *
         * @param builder          the parameters containing the algorithm the generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(MQVAgreementParametersBuilder builder, DHDomainParameters domainParameters)
        {
            this(builder.getAlgorithm(), domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID from an Diffie-Hellman Unified builder.
         *
         * @param builder          the parameters containing the algorithm the generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(DHUAgreementParametersBuilder builder, DHDomainParameters domainParameters)
        {
            this(builder.getAlgorithm(), domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID.
         *
         * @param algorithm        the particular algorithm generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        private KeyGenParameters(FipsAlgorithm algorithm, DHDomainParameters domainParameters)
        {
            super(algorithm);
            this.domainParameters = domainParameters;
        }

        /**
         * Return the Diffie-Hellman domain parameters for this object.
         *
         * @return the Diffie-Hellman domain parameter set.
         */
        public DHDomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * Parameters for Diffie-Hellman based key agreement.
     */
    public static final class AgreementParameters
        extends FipsAgreementParameters
    {
        /**
         * Default constructor which specifies returning the raw secret on agreement calculation.
         */
        AgreementParameters()
        {
            this(null);
        }

        private AgreementParameters(FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM, digestAlgorithm);
        }

        private AgreementParameters(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM, prfAlgorithm, salt);
        }

        private AgreementParameters(FipsAlgorithm agreementAlgorithm, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            super(agreementAlgorithm, kdfType, iv, outputSize);
        }

        /**
         * Add a digest algorithm to process the Z value with.
         *
         * @param digestAlgorithm digest algorithm to use.
         * @return a new parameter set, including the digest algorithm
         */
        public AgreementParameters withDigest(FipsAlgorithm digestAlgorithm)
        {
            return new AgreementParameters(digestAlgorithm);
        }

        /**
         * Add a PRF algorithm and salt to process the Z value with (as in SP 800-56C)
         *
         * @param prfAlgorithm PRF represent the MAC/HMAC algorithm to use.
         * @param salt         the salt to use to initialise the PRF
         * @return a new parameter set, including the digest algorithm
         */
        public AgreementParameters withPRF(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            return new AgreementParameters(prfAlgorithm, salt);
        }

        /**
         * Add a KDF to process the Z value with. The outputSize parameter determines how many bytes
         * will be generated.
         *
         * @param kdfType    KDF algorithm type to use for parameter creation.
         * @param iv         the iv parameter for KDF initialization.
         * @param outputSize the size of the output to be generated from the KDF.
         * @return a new parameter set, the KDF definition.
         */
        public AgreementParameters withKDF(FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            return new AgreementParameters(this.getAlgorithm(), kdfType, iv, outputSize);
        }
    }

    /**
     * Initial builder for MQV parameters.
     */
    public static final class MQVAgreementParametersBuilder
        extends FipsParameters
    {
        MQVAgreementParametersBuilder()
        {
            super(ALGORITHM_MQV);
        }

        /**
         * Constructor for DH MQV parameters from an ephemeral public/private key pair. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralKeyPair       our ephemeral public/private key pair.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricKeyPair ephemeralKeyPair, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters((AsymmetricDHPublicKey)ephemeralKeyPair.getPublicKey(), (AsymmetricDHPrivateKey)ephemeralKeyPair.getPrivateKey(), otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for DH MQV parameters which assumes later calculation of our ephemeral public key. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for DH MQV parameters which results in an agreement returning the raw value.
         *
         * @param ephemeralPublicKey     our ephemeral public key.
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }
    }

    /**
     * Parameters for Diffie-Hellman based key agreement using MQV.
     */
    public static final class MQVAgreementParameters
        extends FipsAgreementParameters
    {
        private final AsymmetricDHPublicKey ephemeralPublicKey;
        private final AsymmetricDHPrivateKey ephemeralPrivateKey;
        private final AsymmetricDHPublicKey otherPartyEphemeralKey;

        private MQVAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_MQV, digestAlgorithm);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private MQVAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM_MQV, prfAlgorithm, salt);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private MQVAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            super(ALGORITHM_MQV, kdfType, iv, outputSize);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        /**
         * Return our ephemeral public key, if present.
         *
         * @return our ephemeral public key, or null.
         */
        public AsymmetricDHPublicKey getEphemeralPublicKey()
        {
            return ephemeralPublicKey;
        }

        /**
         * Return our ephemeral private key.
         *
         * @return our ephemeral private key.
         */
        public AsymmetricDHPrivateKey getEphemeralPrivateKey()
        {
            return ephemeralPrivateKey;
        }

        /**
         * Return the other party's ephemeral public key.
         *
         * @return the other party's ephemeral public key.
         */
        public AsymmetricDHPublicKey getOtherPartyEphemeralKey()
        {
            return otherPartyEphemeralKey;
        }

        /**
         * Add a digest algorithm to process the Z value with.
         *
         * @param digestAlgorithm digest algorithm to use.
         * @return a new parameter set, including the digest algorithm
         */
        public MQVAgreementParameters withDigest(FipsAlgorithm digestAlgorithm)
        {
            return new MQVAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, digestAlgorithm);
        }

        /**
         * Add a PRF algorithm and salt to process the Z value with (as in SP 800-56C)
         *
         * @param prfAlgorithm PRF represent the MAC/HMAC algorithm to use.
         * @param salt         the salt to use to initialise the PRF
         * @return a new parameter set, including the digest algorithm
         */
        public MQVAgreementParameters withPRF(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            return new MQVAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, prfAlgorithm, salt);
        }

        /**
         * Add a KDF to process the Z value with. The outputSize parameter determines how many bytes
         * will be generated.
         *
         * @param kdfType    KDF algorithm type to use for parameter creation.
         * @param iv         the iv parameter for KDF initialization.
         * @param outputSize the size of the output to be generated from the KDF.
         * @return a new parameter set, the KDF definition.
         */
        public MQVAgreementParameters withKDF(FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            return new MQVAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, kdfType, iv, outputSize);
        }
    }

    /**
     * Initial builder for DHU parameters.
     */
    public static final class DHUAgreementParametersBuilder
        extends FipsParameters
    {
        DHUAgreementParametersBuilder()
        {
            super(ALGORITHM_DHU);
        }

        /**
         * Constructor for DH DHU parameters from an ephemeral public/private key pair. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralKeyPair       our ephemeral public/private key pair.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public DHUAgreementParameters using(AsymmetricKeyPair ephemeralKeyPair, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new DHUAgreementParameters((AsymmetricDHPublicKey)ephemeralKeyPair.getPublicKey(), (AsymmetricDHPrivateKey)ephemeralKeyPair.getPrivateKey(), otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for DH DHU parameters which assumes later calculation of our ephemeral public key. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public DHUAgreementParameters using(AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new DHUAgreementParameters(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for DH DHU parameters which results in an agreement returning the raw value.
         *
         * @param ephemeralPublicKey     our ephemeral public key.
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public DHUAgreementParameters using(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new DHUAgreementParameters(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }
    }

    /**
     * Parameters for Diffie-Hellman based key agreement using DHU.
     */
    public static final class DHUAgreementParameters
        extends FipsAgreementParameters
    {
        private final AsymmetricDHPublicKey ephemeralPublicKey;
        private final AsymmetricDHPrivateKey ephemeralPrivateKey;
        private final AsymmetricDHPublicKey otherPartyEphemeralKey;

        private DHUAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_DHU, digestAlgorithm);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private DHUAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM_DHU, prfAlgorithm, salt);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private DHUAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            super(ALGORITHM_DHU, kdfType, iv, outputSize);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        /**
         * Return our ephemeral public key, if present.
         *
         * @return our ephemeral public key, or null.
         */
        public AsymmetricDHPublicKey getEphemeralPublicKey()
        {
            return ephemeralPublicKey;
        }

        /**
         * Return our ephemeral private key.
         *
         * @return our ephemeral private key.
         */
        public AsymmetricDHPrivateKey getEphemeralPrivateKey()
        {
            return ephemeralPrivateKey;
        }

        /**
         * Return the other party's ephemeral public key.
         *
         * @return the other party's ephemeral public key.
         */
        public AsymmetricDHPublicKey getOtherPartyEphemeralKey()
        {
            return otherPartyEphemeralKey;
        }

        /**
         * Add a digest algorithm to process the Z value with.
         *
         * @param digestAlgorithm digest algorithm to use.
         * @return a new parameter set, including the digest algorithm
         */
        public DHUAgreementParameters withDigest(FipsAlgorithm digestAlgorithm)
        {
            return new DHUAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, digestAlgorithm);
        }

        /**
         * Add a PRF algorithm and salt to process the Z value with (as in SP 800-56C)
         *
         * @param prfAlgorithm PRF represent the MAC/HMAC algorithm to use.
         * @param salt         the salt to use to initialise the PRF
         * @return a new parameter set, including the digest algorithm
         */
        public DHUAgreementParameters withPRF(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            return new DHUAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, prfAlgorithm, salt);
        }

        /**
         * Add a KDF to process the Z value with. The outputSize parameter determines how many bytes
         * will be generated.
         *
         * @param kdfType    KDF algorithm type to use for parameter creation.
         * @param iv         the iv parameter for KDF initialization.
         * @param outputSize the size of the output to be generated from the KDF.
         * @return a new parameter set, the KDF definition.
         */
        public DHUAgreementParameters withKDF(FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            return new DHUAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, kdfType, iv, outputSize);
        }
    }

    /**
     * Parameters for generating Diffie-Hellman domain parameters.
     */
    public static final class DomainGenParameters
        extends FipsParameters
    {
        private final int L;
        private final int N;
        private final int certainty;

        private final BigInteger p;
        private final BigInteger q;
        private final byte[] seed;
        private final int usageIndex;

        /**
         * Construct just from strength (L) with a default value for N (160 for 1024, 256 for greater)
         * and a default certainty.
         *
         * @param strength desired length of prime P in bits (the effective key size).
         */
        public DomainGenParameters(int strength)
        {
            this(strength, (strength > 1024) ? 256 : 160, PrimeCertaintyCalculator.getDefaultCertainty(strength));      // Valid N for 2048/3072 , N for 1024
        }

        /**
         * Construct just from strength (L) with a default value for N (160 for 1024, 256 for greater).
         *
         * @param strength  desired length of prime P in bits (the effective key size).
         * @param certainty certainty level for prime number generation.
         */
        public DomainGenParameters(int strength, int certainty)
        {
            this(strength, (strength > 1024) ? 256 : 160, certainty);            // Valid N for 2048/3072 , N for 1024
        }

        /**
         * Construct without a usage index, this will do a random construction of G.
         *
         * @param L         desired length of prime P in bits (the effective key size).
         * @param N         desired length of prime Q in bits.
         * @param certainty certainty level for prime number generation.
         */
        public DomainGenParameters(int L, int N, int certainty)
        {
            this(L, N, certainty, null, null, null, -1);
        }

        /**
         * Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
         *
         * @param L          desired length of prime P in bits (the effective key size).
         * @param N          desired length of prime Q in bits.
         * @param certainty  certainty level for prime number generation.
         * @param usageIndex a valid usage index.
         */
        public DomainGenParameters(int L, int N, int certainty, int usageIndex)
        {
            this(L, N, certainty, null, null, null, usageIndex);
        }

        /**
         * Construct from initial prime values, this will do a random construction of G.
         *
         * @param p the prime P.
         * @param q the prime Q.
         */
        public DomainGenParameters(BigInteger p, BigInteger q)
        {
            this(p.bitLength(), q.bitLength(), 0, p, q, null, -1);
        }

        /**
         * Construct for a specific usage index and initial prime values - this has the effect of using verifiable canonical generation of G.
         *
         * @param p          the prime P.
         * @param q          the prime Q.
         * @param seed       seed used in the generation of (p, q).
         * @param usageIndex a valid usage index.
         */
        public DomainGenParameters(BigInteger p, BigInteger q, byte[] seed, int usageIndex)
        {
            this(p.bitLength(), q.bitLength(), 0, p, q, Arrays.clone(seed), usageIndex);
        }

        private DomainGenParameters(int L, int N, int certainty, BigInteger p, BigInteger q, byte[] seed, int usageIndex)
        {
            super(ALGORITHM);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (p == null && certainty < PrimeCertaintyCalculator.getDefaultCertainty(L))
                {
                    throw new FipsUnapprovedOperationError("Prime generation certainty " + certainty + " inadequate for parameters of " + L + " bits", this.getAlgorithm());
                }
            }

            if (usageIndex > 255)
            {
                throw new IllegalArgumentException("Usage index must be in range 0 to 255 (or -1 to ignore)");
            }

            this.L = L;
            this.N = N;
            this.certainty = certainty;
            this.p = p;
            this.q = q;
            this.seed = seed;
            this.usageIndex = usageIndex;
        }
    }

    /**
     * Generator class for Diffie-Hellman domain parameters.
     */
    public static final class DomainParametersGenerator
    {
        private final SecureRandom random;
        private final DomainGenParameters parameters;
        private final FipsDigestAlgorithm digestAlgorithm;

        /**
         * Default constructor using SHA-256 as the digest.
         *
         * @param parameters domain generation parameters.
         * @param random     a source of randomness for the parameter generation.
         */
        public DomainParametersGenerator(DomainGenParameters parameters, SecureRandom random)
        {
            this(FipsSHS.Algorithm.SHA256, parameters, random);
        }

        /**
         * Base constructor.
         *
         * @param digestAlgorithm digest to use in prime calculations.
         * @param parameters      domain generation parameters.
         * @param random          a source of randomness for the parameter generation.
         */
        public DomainParametersGenerator(FipsDigestAlgorithm digestAlgorithm, DomainGenParameters parameters, SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int effSizeInBits = parameters.L;

                if (effSizeInBits < 2048)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create parameters with unapproved key size [" + effSizeInBits + "]", ALGORITHM);
                }

                Utils.validateRandom(random, Utils.getAsymmetricSecurityStrength(effSizeInBits), ALGORITHM, "Attempt to create parameters with unapproved RNG");
            }

            this.digestAlgorithm = digestAlgorithm;
            this.parameters = parameters;
            this.random = random;
        }

        /**
         * Generate a new set of Diffie-Hellman domain parameters.
         *
         * @return a new set of DHDomainParameters
         */
        public DHDomainParameters generateDomainParameters()
        {
            if (parameters.L < MIN_FIPS_KEY_STRENGTH)
            {
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    throw new FipsUnapprovedOperationError("Requested DH parameter strength too small for approved mode: " + parameters.L);
                }

                DhParametersGenerator pGen = new DhParametersGenerator();

                pGen.init(parameters.L, parameters.certainty, random);

                DhParameters p = pGen.generateParameters();

                return new DHDomainParameters(p.getP(), p.getQ(), p.getG(), p.getJ(), null);
            }

            FipsDSA.DomainGenParameters params = new FipsDSA.DomainGenParameters(parameters.L, parameters.N, parameters.certainty, parameters.p, parameters.q, parameters.seed, parameters.usageIndex);
            FipsDSA.DomainParametersGenerator pGen = new FipsDSA.DomainParametersGenerator(digestAlgorithm, params, random);

            DSADomainParameters domainParameters = pGen.generateDomainParameters();
            DSAValidationParameters vParams = domainParameters.getValidationParameters();

            if (vParams != null)
            {
                return new DHDomainParameters(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), null, new DHValidationParameters(vParams.getSeed(), vParams.getCounter(), vParams.getUsageIndex()));
            }
            else
            {
                return new DHDomainParameters(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG());
            }
        }
    }

    /**
     * Key pair generator for Diffie-Hellman key pairs.
     */
    public static final class KeyPairGenerator
        extends FipsAsymmetricKeyPairGenerator
    {
        private final DhKeyPairGenerator engine = new DhKeyPairGenerator();
        private final DHDomainParameters domainParameters;
        private final DhKeyGenerationParameters param;

        /**
         * Construct a key pair generator for Diffie-Hellman keys,
         *
         * @param keyGenParameters domain parameters and algorithm for the generated key.
         * @param random           a source of randomness for calculating the private value.
         */
        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int sizeInBits = keyGenParameters.domainParameters.getP().bitLength();
                if (sizeInBits < MIN_FIPS_KEY_STRENGTH)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create key of less than " + MIN_FIPS_KEY_STRENGTH + " bits", keyGenParameters.getAlgorithm());
                }

                Utils.validateKeyPairGenRandom(random, Utils.getAsymmetricSecurityStrength(sizeInBits), ALGORITHM);
            }

            this.param = new DhKeyGenerationParameters(random, getDomainParams(keyGenParameters.getDomainParameters()));
            this.domainParameters = keyGenParameters.getDomainParameters();
            this.engine.init(param);
        }

        /**
         * Generate a new Diffie-Hellman key pair.
         *
         * @return a new AsymmetricKeyPair containing a Diffie-Hellman key pair.
         */
        @Override
        public AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey> generateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            DhPublicKeyParameters pubKey = (DhPublicKeyParameters)kp.getPublic();
            DhPrivateKeyParameters prvKey = (DhPrivateKeyParameters)kp.getPrivate();

            FipsAlgorithm algorithm = (FipsAlgorithm)this.getParameters().getAlgorithm();


            // FSM_STATE:5.DH.2, "DH PAIRWISE CONSISTENCY TEST", "The module is performing DH Pairwise Consistency self-test"
            // FSM_TRANS:5.DH.2.0,"CONDITIONAL TEST", "DH PAIRWISE CONSISTENCY TEST", "Invoke DH Pairwise Consistency test"
            validateKeyPair(algorithm, kp);
            // FSM_TRANS:5.DH.2.1,"DH PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "DH Pairwise Consistency test successful"
            // FSM_TRANS:5.DH.2.2,"DH PAIRWISE CONSISTENCY TEST", "SOFT ERROR", "DH Pairwise Consistency test failed"

            return new AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey>(new AsymmetricDHPublicKey(algorithm, domainParameters, pubKey.getY()), new AsymmetricDHPrivateKey(algorithm, domainParameters, prvKey.getX()));
        }
    }

    /**
     * Factory for Agreement operators based on Diffie-Hellman
     */
    public static final class DHAgreementFactory
        extends FipsAgreementFactory<AgreementParameters>
    {
        /**
         * Return an Agreement operator based on the regular Diffie-Hellman algorithm.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for Diffie-Hellman.
         */
        @Override
        public FipsAgreement<AgreementParameters> createAgreement(AsymmetricPrivateKey key, final AgreementParameters parameters)
        {
            AsymmetricDHPrivateKey dhKey = (AsymmetricDHPrivateKey)key;
            DhPrivateKeyParameters lwDhKey = getLwKey(dhKey);

            final DhBasicAgreement dh = AGREEMENT_PROVIDER.createEngine();

            dh.init(lwDhKey);

            return new FipsAgreement<AgreementParameters>()
            {
                @Override
                public AgreementParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricDHPublicKey dhKey = (AsymmetricDHPublicKey)key;
                    DhPublicKeyParameters lwDhKey = new DhPublicKeyParameters(dhKey.getY(), getDomainParams(dhKey.getDomainParameters()));

                    int length = dh.getFieldSize();
                    BigInteger z = dh.calculateAgreement(lwDhKey);
                    byte[] zBytes = BigIntegers.asUnsignedByteArray(length, z);

                    return FipsKDF.processZBytes(zBytes, parameters);
                }
            };
        }
    }

    /**
     * Factory for Unified Agreement operators based on Diffie-Hellman
     */
    public static final class DHUAgreementFactory
        extends FipsAgreementFactory<DHUAgreementParameters>
    {
        /**
         * Return an Agreement operator based on the regular Diffie-Hellman algorithm.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for Diffie-Hellman.
         */
        @Override
        public FipsAgreement<DHUAgreementParameters> createAgreement(AsymmetricPrivateKey key, final DHUAgreementParameters parameters)
        {
            AsymmetricDHPrivateKey dhKey = (AsymmetricDHPrivateKey)key;
            DhuPrivateParameters lwDhKey = new DhuPrivateParameters(getLwKey(dhKey), getLwKey(parameters.ephemeralPrivateKey));

            final DhuBasicAgreement dh = DHU_PROVIDER.createEngine();

            dh.init(lwDhKey);

            return new FipsAgreement<DHUAgreementParameters>()
            {
                @Override
                public DHUAgreementParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricDHPublicKey dhKey = (AsymmetricDHPublicKey)key;
                    DhPublicKeyParameters lwDhKey = new DhPublicKeyParameters(dhKey.getY(), getDomainParams(dhKey.getDomainParameters()));

                    DhuPublicParameters dhuParams = new DhuPublicParameters(lwDhKey,
                        new DhPublicKeyParameters(parameters.otherPartyEphemeralKey.getY(), lwDhKey.getParameters()));

                    byte[] zBytes = dh.calculateAgreement(dhuParams);

                    return FipsKDF.processZBytes(zBytes, parameters);
                }
            };
        }
    }

    /**
     * Factory for Agreement operators based on MQV
     */
    public static final class MQVAgreementFactory
        extends FipsAgreementFactory<MQVAgreementParameters>
    {
        /**
         * Return an Agreement operator based on MQV using Diffie-Hellman keys.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for MQV.
         */
        @Override
        public FipsAgreement<MQVAgreementParameters> createAgreement(AsymmetricPrivateKey key, final MQVAgreementParameters parameters)
        {
            AsymmetricDHPrivateKey dhKey = (AsymmetricDHPrivateKey)key;
            DhPrivateKeyParameters lwDHKey = getLwKey(dhKey);

            final MqvBasicAgreement mqv = MQV_PROVIDER.createEngine();

            mqv.init(new MqvPrivateParameters(lwDHKey, parameters.ephemeralPrivateKey == null ? lwDHKey : getLwKey(parameters.ephemeralPrivateKey)));

            return new FipsAgreement<MQVAgreementParameters>()
            {
                @Override
                public MQVAgreementParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricDHPublicKey dhKey = (AsymmetricDHPublicKey)key;
                    DhPublicKeyParameters lwDhKey = new DhPublicKeyParameters(dhKey.getY(), getDomainParams(dhKey.getDomainParameters()));

                    int length = mqv.getFieldSize();
                    AsymmetricDHPublicKey ephPublicKey = parameters.getOtherPartyEphemeralKey();
                    BigInteger z = mqv.calculateAgreement(new MqvPublicParameters(lwDhKey, new DhPublicKeyParameters(ephPublicKey.getY(), getDomainParams(ephPublicKey.getDomainParameters()))));
                    byte[] zBytes = BigIntegers.asUnsignedByteArray(length, z);

                    return FipsKDF.processZBytes(zBytes, parameters);
                }
            };
        }
    }

    private static void validateKeyPair(FipsAlgorithm algorithm, AsymmetricCipherKeyPair keyPair)
    {
        Variations variation = (algorithm == ALGORITHM) ? Variations.DH : (Variations)algorithm.basicVariation();

        switch (variation)
        {
        case DH:
            SelfTestExecutor.validate(algorithm, keyPair, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    DhBasicAgreement agreement = new DhBasicAgreement();

                    agreement.init(kp.getPrivate());

                    BigInteger agree1 = agreement.calculateAgreement(kp.getPublic());

                    AsymmetricCipherKeyPair testKP = getTestKeyPair(kp);

                    agreement.init(testKP.getPrivate());

                    BigInteger agree2 = agreement.calculateAgreement(testKP.getPublic());

                    agreement.init(kp.getPrivate());

                    BigInteger agree3 = agreement.calculateAgreement(testKP.getPublic());

                    agreement.init(testKP.getPrivate());

                    BigInteger agree4 = agreement.calculateAgreement(kp.getPublic());

                    return !agree1.equals(agree2) && !agree1.equals(agree3) && agree3.equals(agree4);
                }
            });
            break;
        case MQV:
            SelfTestExecutor.validate(algorithm, keyPair, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    MqvBasicAgreement agreement = new MqvBasicAgreement();

                    agreement.init(new MqvPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    BigInteger agree1 = agreement.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)kp.getPublic(), (DhPublicKeyParameters)kp.getPublic()));

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new MqvPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    BigInteger agree2 = agreement.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)testSKP.getPublic(), (DhPublicKeyParameters)testEKP.getPublic()));

                    agreement.init(new MqvPrivateParameters((DhPrivateKeyParameters)testSKP.getPrivate(), (DhPrivateKeyParameters)testEKP.getPrivate()));

                    BigInteger agree3 = agreement.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)kp.getPublic(), (DhPublicKeyParameters)kp.getPublic()));

                    return !agree1.equals(agree2) && agree2.equals(agree3);
                }
            });
            break;
        case DHU:
            SelfTestExecutor.validate(algorithm, keyPair, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    DhuBasicAgreement agreement = new DhuBasicAgreement();

                    agreement.init(new DhuPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    byte[] agree1 = agreement.calculateAgreement(new DhuPublicParameters((DhPublicKeyParameters)kp.getPublic(), (DhPublicKeyParameters)kp.getPublic()));

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new DhuPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    byte[] agree2 = agreement.calculateAgreement(new DhuPublicParameters((DhPublicKeyParameters)testSKP.getPublic(), (DhPublicKeyParameters)testEKP.getPublic()));

                    agreement.init(new DhuPrivateParameters((DhPrivateKeyParameters)testSKP.getPrivate(), (DhPrivateKeyParameters)testEKP.getPrivate()));

                    byte[] agree3 = agreement.calculateAgreement(new DhuPublicParameters((DhPublicKeyParameters)kp.getPublic(), (DhPublicKeyParameters)kp.getPublic()));

                    return !Arrays.areEqual(agree1, agree2) && Arrays.areEqual(agree2, agree3);
                }
            });
            break;
        default:
            throw new IllegalStateException("Unhandled DH algorithm: " + algorithm.getName());
        }
    }

    private static class AgreementProvider
        extends FipsEngineProvider<DhBasicAgreement>
    {
        static final BigInteger expected = new BigInteger("b9fab69d21269e002d6b9aed81176320e597a74894dc0827ac7bab12579425b8fd8f067be4d5a2b77cdd018d267f574df6ba4abf22fa354935acaf9edfac9e382b339b1cadd65e43dd7fa842a1c15116dd48d38015232e1bc3447cf52a39997510aaed5bf7e598f43c1d955c50566edb334af270fc904f38ab2d82024fd86718fbe3cd3d397a49c6be00eec903432855ce755ad5661a3730c281d2b182aaa99b7b77607f8394016a3481ba09109932ce2c964312094a260e9b905aed2a63edf308f95822c9876b61c45648263e4f230fa9f9b49c7916abe698d0a77af04032075b3978423822b919bd46a1e892e5404778133128825958059c9606dfa3b93c6e", 16);

        public DhBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM_DH, new DhBasicAgreement(), new VariantKatTest<DhBasicAgreement>()
            {
                @Override
                void evaluate(DhBasicAgreement engine)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeyPair();

                    AsymmetricCipherKeyPair testOther = getTestKeyPair(kp);

                    engine.init(kp.getPrivate());

                    if (!expected.equals(engine.calculateAgreement(testOther.getPublic())))
                    {
                        fail("KAT DH agreement not verified");
                    }
                }
            });
        }
    }

    private static class MqvProvider
        extends FipsEngineProvider<MqvBasicAgreement>
    {
        static final BigInteger expected = new BigInteger("fb6ad631bae112b5d2a24fa6e821cd3b1f5e70c352b66b83d348a1e4c825bb3b58048f8b1551ee01880d0e513b55e62b2f5389946716561bdb922b86841c311ebe34debb24f0f21a09fa5e383787b36d7c1998b4d6aa9a895859258217c303fedabceb7fe8f1021330a1780e93aca20088394d15b98dfbf5ef3820678feaca7b5c58ebf2b72f0ed4cddd4d8c70ef3a6d34c88f18d4f7bcdca07d5d8194f9db00f7f900c9bf7d7c25cccc94dd94c4a7dc03c3b6fa77dcf2725d3f850da278a5d1d16cf99e2abedbb5ba444bd0bdf7d6decef0d1d1f72f17e255ec9a4edb1c5db833fb65e8b604b00bd542043ed2562c1e1f5cce36fbfe4ba400e61c32622d6dd7", 16);

        public MqvBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM_MQV, new MqvBasicAgreement(), new VariantKatTest<MqvBasicAgreement>()
            {
                @Override
                void evaluate(MqvBasicAgreement engine)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeyPair();

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    engine.init(new MqvPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    BigInteger calculated = engine.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)testSKP.getPublic(), (DhPublicKeyParameters)testEKP.getPublic()));

                    if (!expected.equals(calculated))
                    {
                        fail("KAT DH MQV agreement not verified");
                    }
                }
            });
        }
    }

    private static class DhuProvider
        extends FipsEngineProvider<DhuBasicAgreement>
    {
        static final byte[] expected = Hex.decode("b9fab69d21269e002d6b9aed81176320e597a74894dc0827ac7bab12579425b8fd8f067be4d5a2b77cdd018d267f574df6ba4abf22fa354935acaf9edfac9e382b339b1cadd65e43dd7fa842a1c15116dd48d38015232e1bc3447cf52a39997510aaed5bf7e598f43c1d955c50566edb334af270fc904f38ab2d82024fd86718fbe3cd3d397a49c6be00eec903432855ce755ad5661a3730c281d2b182aaa99b7b77607f8394016a3481ba09109932ce2c964312094a260e9b905aed2a63edf308f95822c9876b61c45648263e4f230fa9f9b49c7916abe698d0a77af04032075b3978423822b919bd46a1e892e5404778133128825958059c9606dfa3b93c6eb9fab69d21269e002d6b9aed81176320e597a74894dc0827ac7bab12579425b8fd8f067be4d5a2b77cdd018d267f574df6ba4abf22fa354935acaf9edfac9e382b339b1cadd65e43dd7fa842a1c15116dd48d38015232e1bc3447cf52a39997510aaed5bf7e598f43c1d955c50566edb334af270fc904f38ab2d82024fd86718fbe3cd3d397a49c6be00eec903432855ce755ad5661a3730c281d2b182aaa99b7b77607f8394016a3481ba09109932ce2c964312094a260e9b905aed2a63edf308f95822c9876b61c45648263e4f230fa9f9b49c7916abe698d0a77af04032075b3978423822b919bd46a1e892e5404778133128825958059c9606dfa3b93c6e");

        public DhuBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM_DHU, new DhuBasicAgreement(), new VariantKatTest<DhuBasicAgreement>()
            {
                @Override
                void evaluate(DhuBasicAgreement engine)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeyPair();

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    engine.init(new DhuPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    byte[] calculated = engine.calculateAgreement(new DhuPublicParameters((DhPublicKeyParameters)testSKP.getPublic(), (DhPublicKeyParameters)testEKP.getPublic()));

                    if (!Arrays.areEqual(expected, calculated))
                    {
                        fail("KAT DH DHU agreement not verified");
                    }
                }
            });
        }
    }

    private static void ffPrimitiveZTest()
    {
        SelfTestExecutor.validate(ALGORITHM, new VariantInternalKatTest(ALGORITHM)
        {
            @Override
            void evaluate()
                throws Exception
            {
                AsymmetricCipherKeyPair kp = getKATKeyPair();

                DhPrivateKeyParameters priv = (DhPrivateKeyParameters)kp.getPrivate();
                DhPublicKeyParameters pub = (DhPublicKeyParameters)kp.getPublic();

                if (!pub.getY().equals(priv.getParameters().getG().modPow(priv.getX(), priv.getParameters().getP())))
                {
                    fail("FF primitive 'Z' computation failed");
                }
            }
        });
    }

    private static AsymmetricCipherKeyPair getKATKeyPair()
    {
        DHDomainParameters dhDp = DHDomainParametersIndex.lookupDomainParameters(DomainParameterID.ffdhe2048);

        DhParameters dhParameters = new DhParameters(dhDp.getP(), dhDp.getG(), dhDp.getQ());
        BigInteger x = new BigInteger("80d54802e42ce811d122ce2657c303013fc33c2f08f8ff1a9c4ebfd1", 16);
        BigInteger y = new BigInteger(
            "f9a4d8edb52efa7ffd00bc2e632b79c69eba8949f7ba23a6feb2d27278e96cbd7fe158484286c07f91144a268539eeffb306844898"
                + "c5efa845070489bcdc756c6858dcb242629f91b2714a33c0efebcb4b0832dba33b12db491dcded86f497094a52a3091a4bdf832d4f"
                + "36cb0cd7ab05e24b2adea4d746806d9776cebe45b0938c8a7f323db0497f865e8d992839ce018d54b68c5808a97fb035c83c304690"
                + "e6fff83dfd13be0186bdf0531cc416f9189fe87b1c92ce569578e9f55c874c0111a1e155f4dd876069424d38c94beb47f890d082eb"
                + "9183a7ce3c6819c420ca91ba969549835314df899fc766ac2acc9d6b9de5b0a9570ca4cfb6187e049fbe6f10", 16);
        return new AsymmetricCipherKeyPair(new DhPublicKeyParameters(y, dhParameters), new DhPrivateKeyParameters(x, dhParameters));
    }

    private static AsymmetricCipherKeyPair getTestKeyPair(AsymmetricCipherKeyPair kp)
    {
        DhPrivateKeyParameters privKey = (DhPrivateKeyParameters)kp.getPrivate();
        DhParameters dhParams = privKey.getParameters();

        BigInteger testD = privKey.getX().multiply(BigInteger.valueOf(7)).mod(privKey.getX());

        if (testD.compareTo(BigInteger.valueOf(2)) < 0)
        {
            testD = new BigInteger("0102030405060708090a0b0c0d0e0f101112131415161718", 16);
        }

        DhPrivateKeyParameters testPriv = new DhPrivateKeyParameters(testD, dhParams);
        DhPublicKeyParameters testPub = new DhPublicKeyParameters(dhParams.getG().modPow(testD, dhParams.getP()), dhParams);

        return new AsymmetricCipherKeyPair(testPub, testPriv);
    }

    private static DhParameters getDomainParams(DHDomainParameters dhParameters)
    {
        return new DhParameters(dhParameters.getP(), dhParameters.getG(), dhParameters.getQ(), dhParameters.getM(), dhParameters.getL(), dhParameters.getJ());
    }

    private static DhPrivateKeyParameters getLwKey(final AsymmetricDHPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<DhPrivateKeyParameters>()
        {
            public DhPrivateKeyParameters run()
            {
                return new DhPrivateKeyParameters(privKey.getX(), getDomainParams(privKey.getDomainParameters()));
            }
        });
    }
}
