package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersID;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersIndex;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.ExtendedDigest;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.crypto.internal.params.EcDhuPrivateParameters;
import org.bouncycastle.crypto.internal.params.EcDhuPublicParameters;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcMqvPrivateParameters;
import org.bouncycastle.crypto.internal.params.EcMqvPublicParameters;
import org.bouncycastle.crypto.internal.params.EcNamedDomainParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.util.test.TestRandomData;

/**
 * Source class for FIPS approved implementations of Elliptic Curve algorithms.
 */
public final class FipsEC
{
    private static final Logger LOG = Logger.getLogger(FipsEC.class.getName());

    private static final int MIN_FIPS_FIELD_SIZE = 224;       // 112 bits of security

    private static final BigInteger TEST_D_OFFSET = new BigInteger("deadbeef", 16);  // offset for generating test key pairs.

    private static final AsymmetricCipherKeyPair katKeyPair = getKATKeyPair();
    private static final AsymmetricCipherKeyPair f2mKatKeyPair = getF2mKATKeyPair();

    private enum Variations
    {
        ECDSA,
        ECDH,
        ECCDH,
        ECMQV,
        ECCDHU,
        ECDDSA
    }

    /**
     * Basic Elliptic Curve key marker, can be used for creating general purpose Elliptic Curve keys.
     */
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("EC");

    private static final FipsAlgorithm ALGORITHM_MQV = new FipsAlgorithm("ECMQV", Variations.ECMQV);

    private static final FipsAlgorithm ALGORITHM_DHU = new FipsAlgorithm("ECCDHU", Variations.ECCDHU);

    /**
     * Elliptic Curve DSA algorithm parameter source - default is SHA-1
     */
    public static final DSAParameters DSA = new DSAParameters(new FipsAlgorithm("ECDSA", Variations.ECDSA), FipsSHS.Algorithm.SHA1);

    /**
     * Elliptic Curve Deterministic DSA algorithm parameter source - default is SHA-1
     */
    public static final DSAParameters DDSA = new DSAParameters(new FipsAlgorithm(ALGORITHM.getName(), FipsEC.Variations.ECDDSA), FipsSHS.Algorithm.SHA1);

    /**
     * Elliptic Curve Diffie-Hellman algorithm parameter source.
     */
    public static final AgreementParameters DH = new AgreementParameters(new FipsAlgorithm("ECDH", Variations.ECDH));
    /**
     * Elliptic Curve cofactor Diffie-Hellman algorithm parameter source.
     */
    public static final AgreementParameters CDH = new AgreementParameters(new FipsAlgorithm("ECCDH", Variations.ECCDH));
    /**
     * Elliptic Curve MQV algorithm parameter source.
     */
    public static final MQVAgreementParametersBuilder MQV = new MQVAgreementParametersBuilder();
    /**
     * Elliptic Curve cofactor Diffie-Hellman Unified algorithm parameter source.
     */
    public static final DHUAgreementParametersBuilder CDHU = new DHUAgreementParametersBuilder();


    private static final DsaProvider DSA_PROVIDER;
    private static final FipsEngineProvider<EcDhBasicAgreement> DH_PROVIDER;
    private static final FipsEngineProvider<EcDhcBasicAgreement> CDH_PROVIDER;
    private static final FipsEngineProvider<EcMqvBasicAgreement> MQV_PROVIDER;
    private static final FipsEngineProvider<EcDhcuBasicAgreement> DHU_PROVIDER;

    static
    {
        DSA_PROVIDER = new DsaProvider();
        DH_PROVIDER = new DhProvider();
        CDH_PROVIDER = new DhcProvider();
        MQV_PROVIDER = new MqvProvider();
        DHU_PROVIDER = new DhuProvider();

        // FSM_STATE:5.EC.0,"EC CVL Primitive 'Z' Gf(p) computation KAT", "The module is performing EC CVL Primitive 'Z' Gf(p) computation KAT verify KAT self-test"
        // FSM_TRANS:5.EC.0.1,"CONDITIONAL TEST", "EC CVL Primitive 'Z' Gf(p) computation KAT", "Invoke EC CVL Primitive 'Z' Gf(p) computation KAT self-test"
        ecPrimitiveZTest();
        // FSM_TRANS:5.EC.0.2,"EC CVL Primitive 'Z' Gf(p) computation KAT", "CONDITIONAL TEST", "EC CVL Primitive 'Z' Gf(p) computation KAT self-test successful completion"
        // FSM_TRANS:5.EC.0.2,"EC CVL Primitive 'Z' Gf(p) computation KAT", "SOFT ERROR", "EC CVL Primitive 'Z' Gf(p) computation KAT self-test failed"

        // FSM_STATE:5.EC.1,"EC CVL Primitive 'Z' Gf(2m) computation KAT", "The module is performing EC CVL Primitive 'Z' Gf(2m) computation KAT verify KAT self-test"
        // FSM_TRANS:5.EC.1.0,"CONDITIONAL TEST", "EC CVL Primitive 'Z' computation KAT", "Invoke EC CVL Primitive 'Z' Gf(2m) computation KAT self-test"
        ecF2mPrimitiveZTest();
        // FSM_TRANS:5.EC.1.1,"EC CVL Primitive 'Z' Gf(2m) computation KAT", "CONDITIONAL TEST", "EC CVL Primitive 'Z' Gf(2m) computation KAT self-test successful completion"
        // FSM_TRANS:5.EC.1.2,"EC CVL Primitive 'Z' Gf(2m) computation KAT", "SOFT ERROR", "EC CVL Primitive 'Z' Gf(2m) computation KAT self-test failed"

        // FSM_STATE:5.EC.2,"ECDSA Gf(p) SIGN VERIFY KAT", "The module is performing ECDSA Gf(p) sign and verify KAT self-test"
        // FSM_TRANS:5.EC.2.0,"CONDITIONAL TEST", "ECDSA SIGN VERIFY KAT", "Invoke ECDSA Gf(p) Sign/Verify  KAT self-test"
        EcDsaSigner signer = DSA_PROVIDER.createEngine(true);
        DSA_PROVIDER.createEngine(false);
        // FSM_TRANS:5.EC.2.1,"ECDSA Gf(p) SIGN VERIFY KAT", "CONDITIONAL TEST", "ECDSA Gf(p) Sign/Verify  KAT self-test successful completion"
        // FSM_TRANS:5.EC.2.2,"ECDSA Gf(p) SIGN VERIFY KAT", "SOFT ERROR", "ECDSA Gf(p) Sign/Verify  KAT self-test failed"

        // FSM_STATE:5.EC.3,"ECDSA Gf(2m) SIGN VERIFY KAT", "The module is performing ECDSA Gf(2m) sign and verify KAT self-test"
        // FSM_TRANS:5.EC.3.0,"CONDITIONAL TEST", "ECDSA SIGN VERIFY KAT", "Invoke ECDSA Gf(2m) Sign/Verify  KAT self-test"
        f2mDsaTest(signer);
        // FSM_TRANS:5.EC.3.1,"ECDSA Gf(2m) SIGN VERIFY KAT", "CONDITIONAL TEST", "ECDSA Gf(2m) Sign/Verify  KAT self-test successful completion"
        // FSM_TRANS:5.EC.3.2,"ECDSA Gf(2m) SIGN VERIFY KAT", "SOFT ERROR", "ECDSA Gf(2m) Sign/Verify  KAT self-test failed"
    }

    /**
     * An enumeration of ECDomainParametersID for the NIST defined EC domain parameters.
     */
    public enum DomainParameterID
        implements ECDomainParametersID
    {
        B571("B-571"),
        B409("B-409"),
        B283("B-283"),
        B233("B-233"),
        K571("K-571"),
        K409("K-409"),
        K283("K-283"),
        K233("K-233"),
        P521("P-521"),
        P384("P-384"),
        P256("P-256"),
        P224("P-224"),
        brainpoolP224r1("brainpoolP224r1"),
        brainpoolP224t1("brainpoolP224t1"),
        brainpoolP256r1("brainpoolP256r1"),
        brainpoolP256t1("brainpoolP256t1"),
        brainpoolP320r1("brainpoolP320r1"),
        brainpoolP320t1("brainpoolP320t1"),
        brainpoolP384r1("brainpoolP384r1"),
        brainpoolP384t1("brainpoolP384t1"),
        brainpoolP512r1("brainpoolP512r1"),
        brainpoolP512t1("brainpoolP512t1"),
        secp256k1("secp256k1");

        private final String curveName;

        DomainParameterID(String curveName)
        {
            this.curveName = curveName;
        }

        public String getCurveName()
        {
            return curveName;
        }
    }

    private static Set<ASN1ObjectIdentifier> approvedKeySet = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        // build approved list for key generation and signature verification based on SP 800-186
        DomainParameterID[] ids = DomainParameterID.values();

        for (int i = 0; i != ids.length; i++)
        {
            String name = ids[i].curveName;

            //The B and K curves are deprecated but still allowed.
            if (Properties.isOverrideSet("org.bouncycastle.ec.enable_f2m") || (name.charAt(0) != 'B' && name.charAt(0) != 'K'))
            {
                approvedKeySet.add(ECNamedCurveTable.getOID(name));
            }
        }
    }

    private FipsEC()
    {

    }

    /**
     * Parameters for EC key pair generation.
     */
    public static final class KeyGenParameters
        extends FipsParameters
    {
        private final ECDomainParameters domainParameters;

        /**
         * Constructor for the default algorithm ID.
         *
         * @param domainParameters EC domain parameters representing the curve any generated keys will be for.
         */
        public KeyGenParameters(ECDomainParameters domainParameters)
        {
            this(ALGORITHM, domainParameters);
        }

        /**
         * Constructor for specifying the DSA algorithm explicitly.
         *
         * @param parameters       the particular parameter set to generate keys for.
         * @param domainParameters EC domain parameters representing the curve any generated keys will be for.
         */
        public KeyGenParameters(DSAParameters parameters, ECDomainParameters domainParameters)
        {
            this(parameters.getAlgorithm(), domainParameters);
        }

        /**
         * Constructor for specifying an Agreement algorithm explicitly.
         *
         * @param parameters       the particular parameter set to generate keys for.
         * @param domainParameters EC domain parameters representing the curve any generated keys will be for.
         */
        public KeyGenParameters(AgreementParameters parameters, ECDomainParameters domainParameters)
        {
            this(parameters.getAlgorithm(), domainParameters);
        }

        /**
         * Constructor for specifying the MQV algorithm explicitly.
         *
         * @param builder          the MQV builder.
         * @param domainParameters EC domain parameters representing the curve any generated keys will be for.
         */
        public KeyGenParameters(MQVAgreementParametersBuilder builder, ECDomainParameters domainParameters)
        {
            this(ALGORITHM_MQV, domainParameters);
        }

        /**
         * Constructor for specifying the CDHU algorithm explicitly.
         *
         * @param builder          the CDHU builder.
         * @param domainParameters EC domain parameters representing the curve any generated keys will be for.
         */
        public KeyGenParameters(DHUAgreementParametersBuilder builder, ECDomainParameters domainParameters)
        {
            this(ALGORITHM_DHU, domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID.
         *
         * @param algorithm        the particular algorithm generated keys are for.
         * @param domainParameters EC domain parameters representing the curve any generated keys will be for.
         */
        KeyGenParameters(FipsAlgorithm algorithm, ECDomainParameters domainParameters)
        {
            super(algorithm);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                validateDomainParameters(domainParameters);
            }
            this.domainParameters = domainParameters;
        }

        /**
         * Return the EC domain parameters for this object.
         *
         * @return the EC domain parameter set.
         */
        public ECDomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    private static void validateDomainParameters(ECDomainParameters domainParameters)
    {
        ASN1ObjectIdentifier paramOid;
        if (domainParameters instanceof NamedECDomainParameters)
        {
            paramOid = ((NamedECDomainParameters)domainParameters).getID();
        }
        else
        {
            paramOid = ECDomainParametersIndex.lookupOID(domainParameters);
        }

        if (paramOid == null || !approvedKeySet.contains(paramOid))
        {
            throw new FipsUnapprovedOperationError("EC domain parameters not on approved list");
        }
    }

    /**
     * Parameters for EC key agreement.
     */
    public static final class AgreementParameters
        extends FipsAgreementParameters
    {
        /**
         * Default constructor which specifies returning the raw secret on agreement calculation.
         *
         * @param agreementAlgorithm the agreement algorithm (DH or CDH).
         */
        AgreementParameters(FipsAlgorithm agreementAlgorithm)
        {
            this(agreementAlgorithm, null);
        }

        private AgreementParameters(FipsAlgorithm agreementAlgorithm, FipsAlgorithm digestAlgorithm)
        {
            super(agreementAlgorithm, digestAlgorithm);
        }

        private AgreementParameters(FipsAlgorithm agreementAlgorithm, FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(agreementAlgorithm, prfAlgorithm, salt);
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
        public AgreementParameters withDigest(FipsDigestAlgorithm digestAlgorithm)
        {
            return new AgreementParameters(this.getAlgorithm(), digestAlgorithm);
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
            return new AgreementParameters(this.getAlgorithm(), prfAlgorithm, salt);
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
     * Parameters for EC DSA signatures.
     */
    public static final class DSAParameters
        extends FipsParameters
    {
        private final FipsDigestAlgorithm digestAlgorithm;

        /**
         * Constructor specifying a digest for signature calculation..
         *
         * @param digestAlgorithm the algorithm ID of the digest to use.
         */
        DSAParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm)
        {
            super(algorithm);

            if (digestAlgorithm == null && CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                PrivilegedUtils.checkPermission(Permissions.TlsNullDigestEnabled);
            }

            if (algorithm.basicVariation() == Variations.ECDDSA && digestAlgorithm == null)
            {
                throw new IllegalArgumentException("ECDDSA cannot be used with a NULL digest");
            }

            this.digestAlgorithm = digestAlgorithm;
        }

        /**
         * Return the algorithm for the underlying digest these parameters will use.
         *
         * @return the digest algorithm
         */
        public FipsDigestAlgorithm getDigestAlgorithm()
        {
            return digestAlgorithm;
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public DSAParameters withDigestAlgorithm(FipsDigestAlgorithm digestAlgorithm)
        {
            return new DSAParameters(getAlgorithm(), digestAlgorithm);
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
         * Constructor for EC MQV parameters from an ephemeral public/private key pair. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralKeyPair       our ephemeral public/private key pair.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricKeyPair ephemeralKeyPair, AsymmetricECPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters((AsymmetricECPublicKey)ephemeralKeyPair.getPublicKey(), (AsymmetricECPrivateKey)ephemeralKeyPair.getPrivateKey(), otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for EC MQV parameters which assumes later calculation of our ephemeral public key. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for EC MQV parameters which results in an agreement returning the raw value.
         *
         * @param ephemeralPublicKey     our ephemeral public key.
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }
    }

    /**
     * Parameters for EC MQV key agreement.
     */
    public static final class MQVAgreementParameters
        extends FipsAgreementParameters
    {
        private final AsymmetricECPublicKey ephemeralPublicKey;
        private final AsymmetricECPrivateKey ephemeralPrivateKey;
        private final AsymmetricECPublicKey otherPartyEphemeralKey;

        private MQVAgreementParameters(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey, FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_MQV, digestAlgorithm);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private MQVAgreementParameters(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey, FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM_MQV, prfAlgorithm, salt);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private MQVAgreementParameters(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
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
        public AsymmetricECPublicKey getEphemeralPublicKey()
        {
            return ephemeralPublicKey;
        }

        /**
         * Return our ephemeral private key.
         *
         * @return our ephemeral private key.
         */
        public AsymmetricECPrivateKey getEphemeralPrivateKey()
        {
            return ephemeralPrivateKey;
        }

        /**
         * Return the other party's ephemeral public key.
         *
         * @return the other party's ephemeral public key.
         */
        public AsymmetricECPublicKey getOtherPartyEphemeralKey()
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
         * @param kdfType    KDF builder type to use for parameter creation.
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
         * Constructor for EC DHU parameters from an ephemeral public/private key pair. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralKeyPair       our ephemeral public/private key pair.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public DHUAgreementParameters using(AsymmetricKeyPair ephemeralKeyPair, AsymmetricECPublicKey otherPartyEphemeralKey)
        {
            return new DHUAgreementParameters((AsymmetricECPublicKey)ephemeralKeyPair.getPublicKey(), (AsymmetricECPrivateKey)ephemeralKeyPair.getPrivateKey(), otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for EC DHU parameters which assumes later calculation of our ephemeral public key. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public DHUAgreementParameters using(AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey)
        {
            return new DHUAgreementParameters(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for EC DHU parameters which results in an agreement returning the raw value.
         *
         * @param ephemeralPublicKey     our ephemeral public key.
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public DHUAgreementParameters using(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey)
        {
            return new DHUAgreementParameters(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }
    }

    /**
     * Parameters for EC DHU key agreement.
     */
    public static final class DHUAgreementParameters
        extends FipsAgreementParameters
    {
        private final AsymmetricECPublicKey ephemeralPublicKey;
        private final AsymmetricECPrivateKey ephemeralPrivateKey;
        private final AsymmetricECPublicKey otherPartyEphemeralKey;

        private DHUAgreementParameters(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey, FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_DHU, digestAlgorithm);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private DHUAgreementParameters(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey, FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM_DHU, prfAlgorithm, salt);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private DHUAgreementParameters(AsymmetricECPublicKey ephemeralPublicKey, AsymmetricECPrivateKey ephemeralPrivateKey, AsymmetricECPublicKey otherPartyEphemeralKey, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
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
        public AsymmetricECPublicKey getEphemeralPublicKey()
        {
            return ephemeralPublicKey;
        }

        /**
         * Return our ephemeral private key.
         *
         * @return our ephemeral private key.
         */
        public AsymmetricECPrivateKey getEphemeralPrivateKey()
        {
            return ephemeralPrivateKey;
        }

        /**
         * Return the other party's ephemeral public key.
         *
         * @return the other party's ephemeral public key.
         */
        public AsymmetricECPublicKey getOtherPartyEphemeralKey()
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
         * @param kdfType    KDF builder type to use for parameter creation.
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
     * EC key pair generator class.
     */
    public static final class KeyPairGenerator
        extends FipsAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricECPublicKey, AsymmetricECPrivateKey>
    {
        private final EcKeyPairGenerator engine = new EcKeyPairGenerator();
        private final ECDomainParameters domainParameters;
        private final EcKeyGenerationParameters param;

        /**
         * Construct a key pair generator for EC keys,
         *
         * @param keyGenParameters domain parameters and algorithm for the generated key.
         * @param random           a source of randomness for calculating the private value.
         */
        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            checkEnabled();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                validateDomainParameters(keyGenParameters.getDomainParameters());

                validateCurveSize(keyGenParameters.getAlgorithm(), keyGenParameters.getDomainParameters());

                Utils.validateKeyPairGenRandom(random, Utils.getECCurveSecurityStrength(keyGenParameters.getDomainParameters().getCurve()), ALGORITHM);
            }

            if (this.getParameters().getAlgorithm().equals(FipsEC.DH.getAlgorithm()) && !ECConstants.ONE.equals(keyGenParameters.domainParameters.getH()))
            {
                this.param = new EcKeyGenerationParameters(getDomainParamsWithInv(keyGenParameters.getDomainParameters()), random);
            }
            else
            {
                this.param = new EcKeyGenerationParameters(getDomainParams(keyGenParameters.getDomainParameters()), random);
            }

            this.domainParameters = keyGenParameters.getDomainParameters();
            this.engine.init(param);
        }

        /**
         * Generate a new EC key pair.
         *
         * @return a new AsymmetricKeyPair containing an EC key pair.
         */
        @Override
        public AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey> generateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            EcPublicKeyParameters pubKey = (EcPublicKeyParameters)kp.getPublic();
            EcPrivateKeyParameters prvKey = (EcPrivateKeyParameters)kp.getPrivate();

            FipsAlgorithm algorithm = this.getParameters().getAlgorithm();

            // FSM_STATE:5.EC.4, "EC PAIRWISE CONSISTENCY TEST", "The module is performing EC Pairwise Consistency self-test"
            // FSM_TRANS:5.EC.4.0,"CONDITIONAL TEST", "EC PAIRWISE CONSISTENCY TEST", "Invoke EC Pairwise Consistency test"
            validateKeyPair(algorithm, kp);
            // FSM_TRANS:5.EC.4.1,"EC PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "EC Pairwise Consistency test successful"
            // FSM_TRANS:5.EC.4.2,"EC PAIRWISE CONSISTENCY TEST", "SOFT ERROR", "EC Pairwise Consistency test failed"

            return new AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey>(new AsymmetricECPublicKey(algorithm, domainParameters, pubKey.getQ()), new AsymmetricECPrivateKey(algorithm, domainParameters, prvKey.getD(), pubKey.getQ()));
        }
    }

    /**
     * Factory for Agreement operators based on EC Diffie-Hellman and Cofactor Diffie-Hellman.
     */
    public static final class DHAgreementFactory
        extends FipsAgreementFactory<AgreementParameters>
    {
        public DHAgreementFactory()
        {
            checkEnabled();
        }

        /**
         * Return an Agreement operator based on Diffie-Hellman using EC keys.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for EC DH.
         */
        @Override
        public FipsAgreement<AgreementParameters> createAgreement(AsymmetricPrivateKey key, AgreementParameters parameters)
        {
            if (parameters.getAlgorithm() == FipsEC.DH.getAlgorithm())
            {
                AsymmetricECPrivateKey ecKey = (AsymmetricECPrivateKey)key;

                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    // only curves with a co-factor of 1 meet SP800-56A r2
                    if (!BigInteger.ONE.equals(ecKey.getDomainParameters().getH()))
                    {
                        throw new FipsUnapprovedOperationError("ECDH can only be executed on curves with a co-factor of 1 in approved mode", key.getAlgorithm());
                    }
                    validateDomainParameters(ecKey.getDomainParameters());

                    validateCurveSize(key.getAlgorithm(), ecKey.getDomainParameters());
                }

                EcPrivateKeyParameters lwECKey;
                if (!BigInteger.ONE.equals(ecKey.getDomainParameters().getH()))
                {
                    // pre-calculate HInv for co-factor clearing.
                    lwECKey = getLwKeyWithInv(ecKey);
                }
                else
                {
                    lwECKey = getLwKey(ecKey);
                }

                EcDhBasicAgreement ecdh = DH_PROVIDER.createEngine();

                ecdh.init(lwECKey);

                return new EcDHAgreement<AgreementParameters>(ecdh, parameters);
            }
            else if (parameters.getAlgorithm() == FipsEC.CDH.getAlgorithm())
            {
                AsymmetricECPrivateKey ecKey = (AsymmetricECPrivateKey)key;

                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    validateDomainParameters(ecKey.getDomainParameters());

                    validateCurveSize(key.getAlgorithm(), ecKey.getDomainParameters());
                }

                EcPrivateKeyParameters lwECKey = getLwKey(ecKey);

                EcDhcBasicAgreement ecdh = CDH_PROVIDER.createEngine();

                ecdh.init(lwECKey);

                return new EcDHAgreement<AgreementParameters>(ecdh, parameters);
            }
            else
            {
                throw new IllegalArgumentException("Incorrect algorithm in parameters for EC DH: " + parameters.getAlgorithm().getName());
            }
        }
    }

    /**
     * Factory for Agreement operators based on EC MQV
     */
    public static final class MQVAgreementFactory
        extends FipsAgreementFactory<MQVAgreementParameters>
    {
        public MQVAgreementFactory()
        {
            checkEnabled();
            if (Properties.isOverrideSet("org.bouncycastle.ec.disable_mqv"))
            {
                throw new UnsupportedOperationException("EC MQV has been disabled by setting \"org.bouncycastle.ec.disable_mqv\"");
            }
        }

        /**
         * Return an Agreement operator based on MQV using EC keys.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for EC MQV.
         */
        @Override
        public FipsAgreement<MQVAgreementParameters> createAgreement(AsymmetricPrivateKey key, MQVAgreementParameters parameters)
        {
            AsymmetricECPrivateKey ecKey = (AsymmetricECPrivateKey)key;

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                validateDomainParameters(ecKey.getDomainParameters());

                validateCurveSize(key.getAlgorithm(), ecKey.getDomainParameters());
            }

            EcPrivateKeyParameters lwECKey = getLwKey(ecKey);

            EcMqvBasicAgreement ecdh = MQV_PROVIDER.createEngine();

            ecdh.init(new EcMqvPrivateParameters(lwECKey, parameters.ephemeralPrivateKey == null ? lwECKey : getLwKey(parameters.ephemeralPrivateKey)));

            return new EcDHAgreement<MQVAgreementParameters>(ecdh, parameters);
        }
    }

    /**
     * Factory for Agreement operators based on EC MQV
     */
    public static final class DHUAgreementFactory
        extends FipsAgreementFactory<DHUAgreementParameters>
    {
        public DHUAgreementFactory()
        {
            checkEnabled();
        }

        /**
         * Return an Agreement operator based on Diffie-Hellman Unified using EC keys.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for EC Diffie-Hellman Unified.
         */
        @Override
        public FipsAgreement<DHUAgreementParameters> createAgreement(AsymmetricPrivateKey key, DHUAgreementParameters parameters)
        {
            AsymmetricECPrivateKey ecKey = (AsymmetricECPrivateKey)key;

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                validateDomainParameters(ecKey.getDomainParameters());

                validateCurveSize(key.getAlgorithm(), ecKey.getDomainParameters());
            }

            EcPrivateKeyParameters lwECKey = getLwKey(ecKey);

            EcDhcuBasicAgreement ecdh = DHU_PROVIDER.createEngine();

            ecdh.init(new EcDhuPrivateParameters(lwECKey, parameters.ephemeralPrivateKey == null ? lwECKey : getLwKey(parameters.ephemeralPrivateKey)));

            return new EcDHUAgreement<DHUAgreementParameters>(ecdh, parameters);
        }
    }

    /**
     * Operator factory for creating EC DSA based signing and verification operators.
     */
    public static final class DSAOperatorFactory
        extends FipsSignatureOperatorFactory<DSAParameters>
    {
        public DSAOperatorFactory()
        {
            checkEnabled();
        }

        /**
         * Return a generator of EC DSA signatures. Note this operator needs to be associated with a SecureRandom to be
         * fully initialised.
         *
         * @param key        the key to initialize the signature generator with.
         * @param parameters parameters required to configure the generation.
         * @return an OutputSignerUsingSecureRandom.
         */
        @Override
        public FipsOutputSignerUsingSecureRandom<DSAParameters> createSigner(AsymmetricPrivateKey key, final DSAParameters parameters)
        {
            AsymmetricECPrivateKey k = (AsymmetricECPrivateKey)key;

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                validateDomainParameters(k.getDomainParameters());

                validateCurveSize(key.getAlgorithm(), k.getDomainParameters());

                Utils.checkDigestAlgorithm(LOG, parameters.getDigestAlgorithm(), "org.bouncycastle.ec.allow_sha1_sig");
            }

            Digest digest = (parameters.digestAlgorithm != null) ? FipsSHS.createDigest(parameters.digestAlgorithm) : new NullDigest();
            EcDsaSigner ecdsaSigner;
            if (parameters.getAlgorithm().basicVariation() == Variations.ECDSA)
            {
                ecdsaSigner = DSA_PROVIDER.createEngine(true);
            }
            else
            {
                ExtendedDigest macDigest = FipsSHS.createDigest(parameters.digestAlgorithm);
                if (macDigest == null)
                {
                    throw new IllegalArgumentException("no HMAC support for chosen digest: " + parameters.digestAlgorithm.getName());
                }
                ecdsaSigner = DSA_PROVIDER.createEngine(parameters.digestAlgorithm, new HMacDsaKCalculator(macDigest));
            }
            final EcPrivateKeyParameters privateKeyParameters = getLwKey(k);

            return new DSAOutputSigner<DSAParameters>(ecdsaSigner, digest, parameters, new DSAOutputSigner.Initializer()
            {
                public void initialize(org.bouncycastle.crypto.internal.DSA signer, SecureRandom random)
                {
                    signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                }
            });
        }

        /**
         * Create a verifier for EC DSA signatures.
         *
         * @param key        the key to initialize the verifier with.
         * @param parameters parameters required to configure the verification.
         * @return an OutputVerifier.
         */
        @Override
        public FipsOutputVerifier<DSAParameters> createVerifier(AsymmetricPublicKey key, final DSAParameters parameters)
        {
            EcDsaSigner ecdsaSigner = DSA_PROVIDER.createEngine(false);
            Digest digest = (parameters.digestAlgorithm != null) ? FipsSHS.createDigest(parameters.digestAlgorithm) : new NullDigest();

            AsymmetricECPublicKey k = (AsymmetricECPublicKey)key;

            EcPublicKeyParameters publicKeyParameters = new EcPublicKeyParameters(k.getW(), getDomainParams(k.getDomainParameters()));

            ecdsaSigner.init(false, publicKeyParameters);

            return new DSAOutputVerifier<DSAParameters>(ecdsaSigner, digest, parameters);
        }

        /**
         * Create a validator for EC DSA signatures.
         *
         * @param key        the key to initialize the verifier with.
         * @param parameters parameters required to configure the verification.
         * @param signature  the signature the data is to be validated against.
         * @return an OutputVerifier.
         */
        public FipsOutputValidator<DSAParameters> createValidator(AsymmetricPublicKey key, final DSAParameters parameters, byte[] signature)
            throws InvalidSignatureException
        {
            EcDsaSigner ecdsaSigner = DSA_PROVIDER.createEngine(false);
            Digest digest = (parameters.digestAlgorithm != null) ? FipsSHS.createDigest(parameters.digestAlgorithm) : new NullDigest();

            AsymmetricECPublicKey k = (AsymmetricECPublicKey)key;

            EcPublicKeyParameters publicKeyParameters = new EcPublicKeyParameters(k.getW(), getDomainParams(k.getDomainParameters()));

            ecdsaSigner.init(false, publicKeyParameters);

            return new DSAOutputValidator<DSAParameters>(ecdsaSigner, digest, parameters, signature);
        }
    }

    private static void checkEnabled()
    {
        if (Properties.isOverrideSet("org.bouncycastle.ec.disable"))
        {
            throw new UnsupportedOperationException("EC has been disabled by setting \"org.bouncycastle.ec.disable\"");
        }
    }

    private static void validateKeyPair(FipsAlgorithm algorithm, AsymmetricCipherKeyPair kp)
    {
        Variations variation = (algorithm == ALGORITHM) ? Variations.ECDSA : (Variations)algorithm.basicVariation();

        switch (variation)
        {
        case ECDSA:
            SelfTestExecutor.validate(algorithm, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    EcDsaSigner signer = new EcDsaSigner();

                    signer.init(true, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                    byte[] message = new byte[32]; // size of a SHA-256 hash
                    message[1] = 1;
                    BigInteger[] rs = signer.generateSignature(message);

                    signer.init(false, kp.getPublic());

                    return signer.verifySignature(message, rs[0], rs[1]);
                }
            });
            break;
        case ECDH:
            SelfTestExecutor.validate(algorithm, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    EcDhBasicAgreement agreement = new EcDhBasicAgreement();

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
        case ECCDH:
            SelfTestExecutor.validate(algorithm, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    EcDhcBasicAgreement agreement = new EcDhcBasicAgreement();

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
        case ECMQV:
            SelfTestExecutor.validate(algorithm, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    EcMqvBasicAgreement agreement = new EcMqvBasicAgreement();

                    agreement.init(new EcMqvPrivateParameters((EcPrivateKeyParameters)kp.getPrivate(), (EcPrivateKeyParameters)kp.getPrivate()));

                    BigInteger agree1 = agreement.calculateAgreement(new EcMqvPublicParameters((EcPublicKeyParameters)kp.getPublic(), (EcPublicKeyParameters)kp.getPublic()));

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new EcMqvPrivateParameters((EcPrivateKeyParameters)kp.getPrivate(), (EcPrivateKeyParameters)kp.getPrivate()));

                    BigInteger agree2 = agreement.calculateAgreement(new EcMqvPublicParameters((EcPublicKeyParameters)testSKP.getPublic(), (EcPublicKeyParameters)testEKP.getPublic()));

                    agreement.init(new EcMqvPrivateParameters((EcPrivateKeyParameters)testSKP.getPrivate(), (EcPrivateKeyParameters)testEKP.getPrivate()));

                    BigInteger agree3 = agreement.calculateAgreement(new EcMqvPublicParameters((EcPublicKeyParameters)kp.getPublic(), (EcPublicKeyParameters)kp.getPublic()));

                    return !agree1.equals(agree2) && agree2.equals(agree3);
                }
            });
            break;
        case ECCDHU:
            SelfTestExecutor.validate(algorithm, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    EcDhcuBasicAgreement agreement = new EcDhcuBasicAgreement();

                    agreement.init(new EcDhuPrivateParameters((EcPrivateKeyParameters)kp.getPrivate(), (EcPrivateKeyParameters)kp.getPrivate()));

                    byte[] agree1 = agreement.calculateAgreement(new EcDhuPublicParameters((EcPublicKeyParameters)kp.getPublic(), (EcPublicKeyParameters)kp.getPublic()));

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new EcDhuPrivateParameters((EcPrivateKeyParameters)kp.getPrivate(), (EcPrivateKeyParameters)kp.getPrivate()));

                    byte[] agree2 = agreement.calculateAgreement(new EcDhuPublicParameters((EcPublicKeyParameters)testSKP.getPublic(), (EcPublicKeyParameters)testEKP.getPublic()));

                    agreement.init(new EcDhuPrivateParameters((EcPrivateKeyParameters)testSKP.getPrivate(), (EcPrivateKeyParameters)testEKP.getPrivate()));

                    byte[] agree3 = agreement.calculateAgreement(new EcDhuPublicParameters((EcPublicKeyParameters)kp.getPublic(), (EcPublicKeyParameters)kp.getPublic()));

                    return !Arrays.areEqual(agree1, agree2) && Arrays.areEqual(agree2, agree3);
                }
            });
            break;
        default:
            throw new IllegalStateException("Unhandled EC algorithm: " + algorithm.getName());
        }
    }

    private static AsymmetricCipherKeyPair getKATKeyPair()
    {
        ECDomainParameters p = ECDomainParametersIndex.lookupDomainParameters(SECObjectIdentifiers.secp256r1);
        EcDomainParameters params = new EcDomainParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH(), p.getSeed()));
        EcPrivateKeyParameters priKey = new EcPrivateKeyParameters(
            new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), // d
            params);

        // Verify the signature
        EcPublicKeyParameters pubKey = new EcPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), // Q
            params);

        return new AsymmetricCipherKeyPair(pubKey, priKey);
    }

    private static AsymmetricCipherKeyPair getF2mKATKeyPair()
    {
        X9ECParameters p = NISTNamedCurves.getByName("B-233");
        EcDomainParameters params = new EcDomainParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH(), p.getSeed()));
        EcPrivateKeyParameters priKey = new EcPrivateKeyParameters(
            new BigInteger("20186677036482506115567393538695075300175221296989956723148347484984008"), // d
            params);

        // Verify the signature
        EcPublicKeyParameters pubKey = new EcPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("03000518bce3b1b492c23094dcd7674c8ea6a3bcb7861bd2fb11be1999b796")), // Q
            params);

        return new AsymmetricCipherKeyPair(pubKey, priKey);
    }

    private static class DsaProvider
        extends FipsEngineProvider<EcDsaSigner>
    {
        private static final BigInteger r = new BigInteger("d73cd3722bae6cc0b39065bb4003d8ece1ef2f7a8a55bfd677234b0b3b902650", 16);
        private static final BigInteger s = new BigInteger("d9c88297fefed8441e08dda69554a6452b8a0bd4a0ea1ddb750499f0c2298c2f", 16);

        public EcDsaSigner createEngine()
        {
            // We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
            return SelfTestExecutor.validate(ALGORITHM, new EcDsaSigner(), new VariantKatTest<EcDsaSigner>()
            {
                void evaluate(EcDsaSigner dsa)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;
                    byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

                    SecureRandom k = new TestRandomData(Hex.decode("a0640d4957f27d091ab1aebc69949d96e5ac2bb283ed5284a5674758b12f08df"));

                    dsa.init(true, new ParametersWithRandom(kp.getPrivate(), k));

                    BigInteger[] sig = dsa.generateSignature(M);

                    if (!sig[0].equals(r) || !sig[1].equals(s))
                    {
                        fail("signature incorrect");
                    }

                    dsa.init(false, kp.getPublic());

                    if (!dsa.verifySignature(M, r, s))
                    {
                        fail("signature fails");
                    }
                }
            });
        }

        public EcDsaSigner createEngine(boolean forSigning)
        {
            // We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
            return SelfTestExecutor.validate(ALGORITHM, new EcDsaSigner(), new VariantKatTest<EcDsaSigner>()
            {
                void evaluate(EcDsaSigner dsa)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;
                    byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

                    if (forSigning)
                    {
                        SecureRandom k = new TestRandomData(Hex.decode("a0640d4957f27d091ab1aebc69949d96e5ac2bb283ed5284a5674758b12f08df"));

                        dsa.init(true, new ParametersWithRandom(kp.getPrivate(), k));

                        BigInteger[] sig = dsa.generateSignature(M);

                        if (!sig[0].equals(r) || !sig[1].equals(s))
                        {
                            fail("signature incorrect");
                        }
                    }
                    else
                    {
                        dsa.init(false, kp.getPublic());

                        if (!dsa.verifySignature(M, r, s))
                        {
                            fail("signature fails");
                        }
                    }
                }
            });
        }

        private static final Map<FipsDigestAlgorithm, BigInteger[]> sigKats = new HashMap<FipsDigestAlgorithm, BigInteger[]>();

        private static final BigInteger rDetSha1 = new BigInteger("9390526f81255b33c950a4419878801be7bf3e5823468bae22bc6e4e86734ffb", 16);
        private static final BigInteger sDetSha1 = new BigInteger("5a4841d6927d9a3bc5c3b37413d798d6d01fba107411ed4b02986d15becf9670", 16);
        private static final BigInteger rDetSha224 = new BigInteger("b2f31c147179b5c27161b2cc7dcbd0f6a2d74dd5ee3b433928a0fe81a0d77d38", 16);
        private static final BigInteger sDetSha224 = new BigInteger("fb6f8c56b1b66bafc4d3294c0df57bc6ec22d12fd22da0bcb4c4741a5d10a2fd", 16);
        private static final BigInteger rDetSha256 = new BigInteger("522bb76fa0ab8f043b6be30f099b56b12bcc69f247f5a5a39cec4b02fd08b87b", 16);
        private static final BigInteger sDetSha256 = new BigInteger("32fc666aa042b991aa86a1c5f4697418484f81f91485bf8ffa51590131a7a78f", 16);
        private static final BigInteger rDetSha384 = new BigInteger("6d6b76dbf798f27e8950bd0fe6c228d78852d513613423a3ee085cca56bea0ba", 16);
        private static final BigInteger sDetSha384 = new BigInteger("71547e92702e2b6c770dc542144c8dfc5b31e6c8a8c5a8929915d0ec12cfff5", 16);
        private static final BigInteger rDetSha512 = new BigInteger("caa9a9f66852c1744fb40f1b59835337eabb0148f97f1f867ad8246cd282d0a2", 16);
        private static final BigInteger sDetSha512 = new BigInteger("946d6b64469b25d059ec8083e5cda36e4443dc98d2289a890587f49590360814", 16);
        private static final BigInteger rDetSha512_224 = new BigInteger("b92d4c176762df6027431e2b08686eeb3395cde69cf3872ff1ba864caa7f32cd", 16);
        private static final BigInteger sDetSha512_224 = new BigInteger("ab7af8d8646e917744ea5bda468e28d0d413c207135b6604862412a2ef704c40", 16);
        private static final BigInteger rDetSha512_256 = new BigInteger("57e55a88f7ea9f036ea64bd247029c821b10fd167ba6442ba2a9d89660f6c605", 16);
        private static final BigInteger sDetSha512_256 = new BigInteger("763419c86554203db3de94642877b4d74d6ac37f6cf09b58978a7b945243928e", 16);
        private static final BigInteger rDetSha3_224 = new BigInteger("5330797301a8abe67a44cc890f160fabf41dea224d7f9b139f1b3ca48b113fae", 16);
        private static final BigInteger sDetSha3_224 = new BigInteger("a95a916fec76fbbe67fa4f3903d22c20069b46e90aa15bb49e7ff27b1f7a6505", 16);
        private static final BigInteger rDetSha3_256 = new BigInteger("c79d5244c610b6f0f8ca6d848ea77e67c2cc7087b9617e9c93d52a08ee03d70", 16);
        private static final BigInteger sDetSha3_256 = new BigInteger("1ac50fbb370c75ad97d81ca98018e3422209d57fecab4427f236b67f3a148fa7", 16);
        private static final BigInteger rDetSha3_384 = new BigInteger("9f4a4e59dc8ba7dcc35ff3542c37e5d5f3a9df697573cc38156e103731181977", 16);
        private static final BigInteger sDetSha3_384 = new BigInteger("9743b86945e035447613bc3ea86885bb4855b8ff638e02bb841b4685dcc04605", 16);
        private static final BigInteger rDetSha3_512 = new BigInteger("597d41ed723bc9827cab2b011a9a540aa4082024f347d3d168166e29df5029d4", 16);
        private static final BigInteger sDetSha3_512 = new BigInteger("627f032d2252d942fabf533df4f11817fac3fd1a53559d2689a0cc368b22824e", 16);
        private static final BigInteger rDetShake128 = new BigInteger("cacabf72ff5250ff193e201b65a9c0d25ae52a4d02f67f3ad6c817fbd962c254", 16);
        private static final BigInteger sDetShake128 = new BigInteger("96ec4a5b73603df896adc6965e18be02c326cc922b3dd399c1309b0bf14aa0e4", 16);
        private static final BigInteger rDetShake256 = new BigInteger("680d40574d06cbf3c2502b76f91ebe16d4eca4607554d0036b50446526118111", 16);
        private static final BigInteger sDetShake256 = new BigInteger("bedaf371aa2de86dd3d201db52c351f6f0c5fe132a355db0e26f3922e691439e", 16);
        
        static
        {
            sigKats.put(FipsSHS.Algorithm.SHA1, new BigInteger[] { rDetSha1, sDetSha1 });
            sigKats.put(FipsSHS.Algorithm.SHA224, new BigInteger[] { rDetSha224, sDetSha224 });
            sigKats.put(FipsSHS.Algorithm.SHA256, new BigInteger[] { rDetSha256, sDetSha256 });
            sigKats.put(FipsSHS.Algorithm.SHA384, new BigInteger[] { rDetSha384, sDetSha384 });
            sigKats.put(FipsSHS.Algorithm.SHA512, new BigInteger[] { rDetSha512, sDetSha512 });
            sigKats.put(FipsSHS.Algorithm.SHA512_224, new BigInteger[] { rDetSha512_224, sDetSha512_224 });
            sigKats.put(FipsSHS.Algorithm.SHA512_256, new BigInteger[] { rDetSha512_256, sDetSha512_256 });
            sigKats.put(FipsSHS.Algorithm.SHA3_224, new BigInteger[] { rDetSha3_224, sDetSha3_224 });
            sigKats.put(FipsSHS.Algorithm.SHA3_256, new BigInteger[] { rDetSha3_256, sDetSha3_256 });
            sigKats.put(FipsSHS.Algorithm.SHA3_384, new BigInteger[] { rDetSha3_384, sDetSha3_384 });
            sigKats.put(FipsSHS.Algorithm.SHA3_512, new BigInteger[] { rDetSha3_512, sDetSha3_512 });
            sigKats.put(FipsSHS.Algorithm.SHAKE128, new BigInteger[] { rDetShake128, sDetShake128 });
            sigKats.put(FipsSHS.Algorithm.SHAKE256, new BigInteger[] { rDetShake256, sDetShake256 });
        }
        
        public EcDsaSigner createEngine(final FipsDigestAlgorithm digest, HMacDsaKCalculator calculator)
        {
            // We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
            return SelfTestExecutor.validate(ALGORITHM, new EcDsaSigner(calculator), new VariantKatTest<EcDsaSigner>()
            {
                void evaluate(EcDsaSigner dsa)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;
                    byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

                    dsa.init(true, kp.getPrivate());

                    BigInteger[] sig = dsa.generateSignature(M);
                    BigInteger[] katSig = sigKats.get(digest);

                    if (katSig != null)
                    {
                        // we can just use the KAT.
                        if (!sig[0].equals(katSig[0]) || !sig[1].equals(katSig[1]))
                        {
                            fail("signature incorrect");
                        }
                    }
                    else
                    {
                        // we need to confirm verification
                        dsa.init(false, kp.getPublic());

                        if (!dsa.verifySignature(M, sig[0], sig[1]))
                        {
                            fail("signature check failed");
                        }
                    }
                }
            });
        }
    }

    private static void f2mDsaTest(EcDsaSigner signer)
    {
        SelfTestExecutor.validate(ALGORITHM, signer, new VariantKatTest<EcDsaSigner>()
        {
            void evaluate(EcDsaSigner dsa)
                throws Exception
            {
                BigInteger f2mR = new BigInteger(1, Hex.decode("d001312179360f7a557d4686e2faf9740fd3289edbafb5e551402cf1b0"));
                BigInteger f2mS = new BigInteger(1, Hex.decode("9d4c2f24b50ce6b9ac725c7833c495fe703296c038dab05ea7af06cafe"));

                AsymmetricCipherKeyPair kp = f2mKatKeyPair;

                SecureRandom k = new TestRandomBigInteger(233, Hex.decode("640d4957f27d091ab1aebc69949d96e5ac2bb283ed5284a5674758b12f"));
                byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

                dsa.init(true, new ParametersWithRandom(kp.getPrivate(), k));

                BigInteger[] sig = dsa.generateSignature(M);

                if (!sig[0].equals(f2mR) || !sig[1].equals(f2mS))
                {
                    fail("F2m signature incorrect");
                }

                dsa.init(false, kp.getPublic());
                if (!dsa.verifySignature(M, sig[0], sig[1]))
                {
                    fail("F2m signature fails");
                }
            }
        });
    }

    private static class DhProvider
        extends FipsEngineProvider<EcDhBasicAgreement>
    {
        static BigInteger expected = new BigInteger("cad5c428ea0645794bc5634549e08a3ed563bd0cf32e909862e08b41d4b6fc17", 16);

        public EcDhBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new EcDhBasicAgreement(), new VariantKatTest<EcDhBasicAgreement>()
            {
                void evaluate(EcDhBasicAgreement agreement)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;

                    AsymmetricCipherKeyPair testOther = getTestKeyPair(kp);

                    agreement.init(kp.getPrivate());

                    if (!expected.equals(agreement.calculateAgreement(testOther.getPublic())))
                    {
                        fail("KAT ECDH agreement not verified");
                    }
                }
            });
        }
    }

    private static class DhcProvider
        extends FipsEngineProvider<EcDhcBasicAgreement>
    {
        static final BigInteger expected = new BigInteger("cad5c428ea0645794bc5634549e08a3ed563bd0cf32e909862e08b41d4b6fc17", 16);

        public EcDhcBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new EcDhcBasicAgreement(), new VariantKatTest<EcDhcBasicAgreement>()
            {
                void evaluate(EcDhcBasicAgreement agreement)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;

                    AsymmetricCipherKeyPair testOther = getTestKeyPair(kp);

                    agreement.init(kp.getPrivate());

                    if (!expected.equals(agreement.calculateAgreement(testOther.getPublic())))
                    {
                        fail("KAT ECDHC agreement not verified");
                    }
                }
            });
        }
    }

    private static class MqvProvider
        extends FipsEngineProvider<EcMqvBasicAgreement>
    {
        static final BigInteger expected = new BigInteger("8cae3483c0d3dac87d1c1d32be8e7b7a3c1558bd01cb7e7bb37c1c81126b0f98", 16);

        public EcMqvBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new EcMqvBasicAgreement(), new VariantKatTest<EcMqvBasicAgreement>()
            {
                void evaluate(EcMqvBasicAgreement agreement)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new EcMqvPrivateParameters((EcPrivateKeyParameters)kp.getPrivate(), (EcPrivateKeyParameters)kp.getPrivate()));

                    BigInteger calculated = agreement.calculateAgreement(new EcMqvPublicParameters((EcPublicKeyParameters)testSKP.getPublic(), (EcPublicKeyParameters)testEKP.getPublic()));

                    if (!expected.equals(calculated))
                    {
                        fail("KAT ECMQV agreement not verified");
                    }
                }
            });
        }
    }

    private static class DhuProvider
        extends FipsEngineProvider<EcDhcuBasicAgreement>
    {
        static final byte[] expected = Hex.decode("cad5c428ea0645794bc5634549e08a3ed563bd0cf32e909862e08b41d4b6fc17cad5c428ea0645794bc5634549e08a3ed563bd0cf32e909862e08b41d4b6fc17");

        public EcDhcuBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new EcDhcuBasicAgreement(), new VariantKatTest<EcDhcuBasicAgreement>()
            {
                void evaluate(EcDhcuBasicAgreement agreement)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = katKeyPair;

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new EcDhuPrivateParameters((EcPrivateKeyParameters)kp.getPrivate(), (EcPrivateKeyParameters)kp.getPrivate()));

                    byte[] calculated = agreement.calculateAgreement(new EcDhuPublicParameters((EcPublicKeyParameters)testSKP.getPublic(), (EcPublicKeyParameters)testEKP.getPublic()));

                    if (!Arrays.areEqual(expected, calculated))
                    {
                        fail("KAT ECCDHU agreement not verified");
                    }
                }
            });
        }
    }

    private static void ecPrimitiveZTest()
    {
        SelfTestExecutor.validate(ALGORITHM, new VariantInternalKatTest(ALGORITHM)
        {
            @Override
            void evaluate()
                throws Exception
            {
                X9ECParameters p = NISTNamedCurves.getByName("P-256");
                ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH(), p.getSeed());
                BigInteger dValue = new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008");

                ECPoint Q = params.getCurve().decodePoint(Hex.decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D"));

                if (!Q.equals(params.getG().multiply(dValue)))
                {
                    fail("EC primitive 'Z' computation failed");
                }
            }
        });
    }

    private static void ecF2mPrimitiveZTest()
    {
        SelfTestExecutor.validate(ALGORITHM, new VariantInternalKatTest(ALGORITHM)
        {
            @Override
            void evaluate()
                throws Exception
            {
                X9ECParameters p = NISTNamedCurves.getByName("B-233");
                ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH(), p.getSeed());
                BigInteger dValue = new BigInteger("20186677036482506115567393538695075300175221296989956723148347484984008");

                ECPoint Q = params.getCurve().decodePoint(Hex.decode("03000518bce3b1b492c23094dcd7674c8ea6a3bcb7861bd2fb11be1999b796"));

                if (!Q.equals(params.getG().multiply(dValue)))
                {
                    fail("EC primitive F2m 'Z' computation failed");
                }
            }
        });
    }

    private static AsymmetricCipherKeyPair getTestKeyPair(AsymmetricCipherKeyPair kp)
    {
        EcPrivateKeyParameters privKey = (EcPrivateKeyParameters)kp.getPrivate();
        EcDomainParameters ecDomainParameters = privKey.getParameters();

        BigInteger testD = privKey.getD().add(TEST_D_OFFSET).mod(ecDomainParameters.getN());

        if (testD.compareTo(ECConstants.TWO) < 0)
        {
            testD = testD.add(TEST_D_OFFSET);
        }

        EcPrivateKeyParameters testPriv = new EcPrivateKeyParameters(testD, ecDomainParameters);
        EcPublicKeyParameters testPub = new EcPublicKeyParameters(ecDomainParameters.getG().multiply(testD), ecDomainParameters);

        return new AsymmetricCipherKeyPair(testPub, testPriv);
    }

    private static void validateCurveSize(Algorithm algorithm, ECDomainParameters domainParameters)
    {
        // curve size needs to offer 112 bits of security.
        if (domainParameters.getCurve().getFieldSize() < MIN_FIPS_FIELD_SIZE)
        {
            throw new FipsUnapprovedOperationError("Attempt to use curve with field size less than " + MIN_FIPS_FIELD_SIZE + " bits", algorithm);
        }
    }

    private static EcDomainParameters getDomainParams(ECDomainParameters curveParams)
    {
        if (curveParams instanceof NamedECDomainParameters)
        {
            return new EcNamedDomainParameters((NamedECDomainParameters)curveParams);
        }
        return new EcDomainParameters(curveParams);
    }

    private static EcPrivateKeyParameters getLwKey(final AsymmetricECPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<EcPrivateKeyParameters>()
        {
            public EcPrivateKeyParameters run()
            {
                return new EcPrivateKeyParameters(privKey.getS(), getDomainParams(privKey.getDomainParameters()));
            }
        });
    }

    private static EcDomainParameters getDomainParamsWithInv(ECDomainParameters curveParams)
    {
        if (curveParams instanceof NamedECDomainParameters)
        {
            return new EcNamedDomainParameters((NamedECDomainParameters)curveParams, curveParams.getInverseH());
        }
        return new EcDomainParameters(curveParams, curveParams.getInverseH());
    }

    private static EcPrivateKeyParameters getLwKeyWithInv(final AsymmetricECPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<EcPrivateKeyParameters>()
        {
            public EcPrivateKeyParameters run()
            {
                return new EcPrivateKeyParameters(privKey.getS(), getDomainParamsWithInv(privKey.getDomainParameters()));
            }
        });
    }
}
