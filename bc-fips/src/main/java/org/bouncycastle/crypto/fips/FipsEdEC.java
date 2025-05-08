package org.bouncycastle.crypto.fips;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.crypto.internal.Xof;
import org.bouncycastle.crypto.internal.io.SignerOutputStream;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of Edwards Elliptic Curve based algorithms.
 */
public final class FipsEdEC
{
    public static final byte[] ZERO_CONTEXT = new byte[0];

    // from RFC 8032
    private static final Ed448PrivateKeyParameters ed448KatPriv = new Ed448PrivateKeyParameters(
        Hex.decode("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42" +
            "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49"));
    private static final Ed448PublicKeyParameters ed448KatPub = new Ed448PublicKeyParameters(
        Hex.decode("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743" +
            "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880"));

    private static final Ed25519PrivateKeyParameters ed25519KatPriv = new Ed25519PrivateKeyParameters(
        Hex.decode("ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560"));
    private static final Ed25519PublicKeyParameters ed25519KatPub = new Ed25519PublicKeyParameters(
        Hex.decode("0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772"));

    private static final byte[] data = Hex.decode("f726936d19c800494e3fdaff20b276a8");

    private static final byte[] katEd25519 = Hex.decode("daca536d5370fdada0b14cfbe1f25c1199f67b18999ce05a50cc66a83c79984421fcc8d8dfde4cd57e00d96f1d7151f279c34801b17ec40c461c0bc800557106");
    private static final byte[] katEd448 = Hex.decode("f45d7a3e96ea099edffc99d0980242f64a33ea7b0ef09fa0c621c65103f464ebe17a716a0246b2325cd20b577f6c2f25d3a509f23dca1f9f80d5fb4167cd27ab461b344d82e0f93dc844718763b36b0dd9a3561e7e2f3983cfb7bbe0c83cdfc93060a3bca04a9f2dfabfab069065f5ed0e00");

    private static final byte[] katEd25519ph = Hex.decode("80ccf9c08ce4e6db71491cf99b8b3445d79a231e8f8383f3a70db733bdea03eb2c29ccb8b20bd9a65265393e21970d5798354d1a9569c9df29d641b7b9d52802");
    private static final byte[] katEd448ph = Hex.decode("fe4a12d88f6878ee10028444ae0185d73c8d3e385a600d39a081b5953f952f8a538ceacb353b88aac79e39caaf41eb4f8b51ac4790e3e8258048f58bdf9179da473bfc227c41bf866f3a0944974f1ac723132d2156b0a66703553cd09e5512a807c469803e50c6d5607c2772864cd34a0f00");

    private FipsEdEC()
    {

    }

    public static final class Algorithm
    {
        private Algorithm()
        {

        }

        private static final FipsAlgorithm Pure = new FipsAlgorithm("EdDSA");
        private static final FipsAlgorithm Hash = new FipsAlgorithm("EdDSAph");

        public static final FipsAlgorithm Ed448 = new FipsAlgorithm("Ed448", Variations.Ed448);
        public static final FipsAlgorithm Ed448ph = new FipsAlgorithm("Ed448ph", Variations.Ed448ph);
        public static final FipsAlgorithm Ed25519 = new FipsAlgorithm("Ed25519", Variations.Ed25519);
        public static final FipsAlgorithm Ed25519ph = new FipsAlgorithm("Ed25519ph", Variations.Ed25519ph);
    }

    public static final Parameters EdDSA = new Parameters(Algorithm.Pure);
    public static final Parameters EdDSAph = new Parameters(Algorithm.Hash);
    public static final Parameters Ed448 = new Parameters(Algorithm.Ed448);
    public static final Parameters Ed448ph = new Parameters(Algorithm.Ed448ph);
    public static final Parameters Ed25519 = new Parameters(Algorithm.Ed25519);
    public static final Parameters Ed25519ph = new Parameters(Algorithm.Ed25519ph);

    private enum Variations
    {
        Ed448,
        Ed448ph,
        Ed25519,
        Ed25519ph
    }

    public static final int Ed448_PUBLIC_KEY_SIZE = Ed448PublicKeyParameters.KEY_SIZE;
    public static final int Ed25519_PUBLIC_KEY_SIZE = Ed25519PublicKeyParameters.KEY_SIZE;

    public static final int Ed448_PRIVATE_KEY_SIZE = Ed448PrivateKeyParameters.KEY_SIZE;
    public static final int Ed25519_PRIVATE_KEY_SIZE = Ed25519PrivateKeyParameters.KEY_SIZE;

    private static final EdDSAProvider edDsaProvider = new EdDSAProvider();
    private static final EdDSAphProvider edDsaPhProvider = new EdDSAphProvider();

    static
    {

        // FSM_STATE:5.EdDSA.0,"EdDSA SIGN VERIFY KATs", "The module is performing EdDSA sign and verify KAT self-test"
        // FSM_TRANS:5.EdDSA.0.0,"CONDITIONAL TEST", "EdDSA SIGN VERIFY KAT", "Invoke EdDSA Sign/Verify  KAT self-test"
        edDsaProvider.createEngine(Variations.Ed25519, ZERO_CONTEXT);
        edDsaProvider.createEngine(Variations.Ed448, ZERO_CONTEXT);
        // FSM_TRANS:5.EdDSA.0.1,"EdDSA SIGN VERIFY KAT", "CONDITIONAL TEST", "ECDSA Sign/Verify  KAT self-test successful completion"
        // FSM_TRANS:5.EdDSA.0.2,"EdDSA SIGN VERIFY KAT", "SOFT ERROR", "ECDSA Sign/Verify  KAT self-test failed"

        // FSM_STATE:5.EdDSA.1,"EdDSAph SIGN VERIFY KAT", "The module is performing EdDSA pre-hash sign and verify KAT self-test"
        // FSM_TRANS:5.EdDSA.1.0,"CONDITIONAL TEST", "ECDSAph SIGN VERIFY KAT", "Invoke EdDSA pre-hash Sign/Verify  KAT self-test"
        edDsaPhProvider.createEngine(Variations.Ed25519ph, ZERO_CONTEXT);
        edDsaPhProvider.createEngine(Variations.Ed448ph, ZERO_CONTEXT);
        // FSM_TRANS:5.EdDSA.1.1,"EdDSA SIGN VERIFY KAT", "CONDITIONAL TEST", "EdDSA pre-hash Sign/Verify  KAT self-test successful completion"
        // FSM_TRANS:5.EdDSA.1.2,"EdDSA SIGN VERIFY KAT", "SOFT ERROR", "EdDSA pre-hash Sign/Verify  KAT self-test failed"
    }

    /**
     * Edwards Curve key pair generation parameters.
     */
    public static class Parameters
        extends FipsParameters
    {
        /**
         * Base constructor.
         *
         * @param algorithm the EdEC domain parameters algorithm.
         */
        Parameters(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Edwards Curve parameters with context vector
     */
    public static class ParametersWithContext
        extends Parameters
    {
        private final byte[] context;

        /**
         * Base constructor.
         *
         * @param algorithm the EdEC domain parameters algorithm.
         */
        public ParametersWithContext(FipsAlgorithm algorithm, byte[] context)
        {
            super(algorithm);
            if (algorithm.equals(Algorithm.Ed25519))
            {
                throw new IllegalArgumentException("context cannot be used with Ed25519");
            }
            if (context == null)
            {
                throw new IllegalArgumentException("context cannot be null");
            }
            if (context.length > 255)
            {
                throw new IllegalArgumentException("context > 255");
            }

            this.context = Arrays.clone(context);
        }

        /**
         * Return the context value.
         *
         * @return context value.
         */
        public byte[] getContext()
        {
            return Arrays.clone(context);
        }
    }

    /**
     * Edwards Curve DSA key pair generator.
     */
    public static final class EdDSAKeyPairGenerator
        extends FipsAsymmetricKeyPairGenerator<Parameters, AsymmetricEdDSAPublicKey, AsymmetricEdDSAPrivateKey>
    {
        private final Variations variation;
        private final AsymmetricCipherKeyPairGenerator kpGen;

        public EdDSAKeyPairGenerator(Parameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            if (keyGenParameters.getAlgorithm().basicVariation() == null)
            {
                throw new IllegalArgumentException("key generation parameters must specify Ed25519 or Ed448");
            }

            int strength;
            switch ((Variations)keyGenParameters.getAlgorithm().basicVariation())
            {
            case Ed448:
            case Ed448ph:
                this.variation = Variations.Ed448;
                this.kpGen = new Ed448KeyPairGenerator();
                strength = 224;
                break;
            case Ed25519:
            case Ed25519ph:
                this.variation = Variations.Ed25519;
                this.kpGen = new Ed25519KeyPairGenerator();
                strength = 128;
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateKeyPairGenRandom(random, strength, keyGenParameters.getAlgorithm());
            }

            kpGen.init(new KeyGenerationParameters(random, 0));    // strength ignored
        }

        public AsymmetricKeyPair generateKeyPair()
        {
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            validateSigningKeyPair(kp);

            switch (variation)
            {
            case Ed448:
                return new AsymmetricKeyPair(
                    new AsymmetricEdDSAPublicKey(Ed448.getAlgorithm(), ((Ed448PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricEdDSAPrivateKey(Ed448.getAlgorithm(), ((Ed448PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((Ed448PublicKeyParameters)kp.getPublic()).getEncoded()));
            case Ed25519:
                return new AsymmetricKeyPair(
                    new AsymmetricEdDSAPublicKey(Ed25519.getAlgorithm(), ((Ed25519PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricEdDSAPrivateKey(Ed25519.getAlgorithm(), ((Ed25519PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((Ed25519PublicKeyParameters)kp.getPublic()).getEncoded()));
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }
        }
    }

    /**
     * Operator factory for creating Edwards Curve DSA based signing and verification operators.
     */
    public static final class EdDSAOperatorFactory
        extends FipsSignatureOperatorFactory<Parameters>
    {
        public EdDSAOperatorFactory()
        {
        }

        @Override
        public FipsOutputSigner<Parameters> createSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final Signer signer = createEngine((FipsAlgorithm)key.getAlgorithm(), parameters);
            final FipsAlgorithm algorithm = getSignatureAlgorithm((FipsAlgorithm)key.getAlgorithm(), parameters);

            signer.init(true, getLwKey((AsymmetricEdDSAPrivateKey)key));

            return new FipsOutputSigner<Parameters>()
            {

                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getSigningStream()
                {
                    return new SignerOutputStream(algorithm.getName(), signer);
                }

                public byte[] getSignature()
                    throws PlainInputProcessingException
                {
                    try
                    {
                        return signer.generateSignature();
                    }
                    catch (Exception e)
                    {
                        throw new PlainInputProcessingException("Unable to create signature: " + e.getMessage(), e);
                    }
                }

                public int getSignature(byte[] output, int off)
                    throws PlainInputProcessingException
                {
                    byte[] sig = getSignature();

                    System.arraycopy(sig, 0, output, off, sig.length);

                    return sig.length;
                }
            };
        }

        @Override
        public FipsOutputVerifier<Parameters> createVerifier(AsymmetricPublicKey key, final Parameters parameters)
        {
            final FipsAlgorithm algorithm = getSignatureAlgorithm((FipsAlgorithm)key.getAlgorithm(), parameters);
            final Signer signer = getVerifySigner((AsymmetricEdDSAPublicKey)key, algorithm, parameters);

            return new FipsOutputVerifier<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getVerifyingStream()
                {
                    return new SignerOutputStream(algorithm.getName(), signer);
                }

                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    return signer.verifySignature(signature);
                }
            };
        }

        @Override
        public FipsOutputValidator<Parameters> createValidator(AsymmetricPublicKey key, final Parameters parameters, final byte[] signature)
        {
            final FipsAlgorithm algorithm = getSignatureAlgorithm((FipsAlgorithm)key.getAlgorithm(), parameters);
            final Signer signer = getVerifySigner((AsymmetricEdDSAPublicKey)key, algorithm, parameters);

            return new FipsOutputValidator<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getValidatingStream()
                {
                    return new SignerOutputStream(algorithm.getName(), signer);
                }

                public boolean isValidated()
                {
                    try
                    {
                        return signer.verifySignature(signature);
                    }
                    catch (InvalidSignatureException e)
                    {
                        return false;
                    }
                }
            };
        }

        private Signer getVerifySigner(AsymmetricEdDSAPublicKey key, FipsAlgorithm algorithm, Parameters parameters)
        {
            Signer signer = createEngine((FipsAlgorithm)key.getAlgorithm(), parameters);

            signer.init(false, getLwKey(key));

            return signer;
        }

        private Signer createEngine(FipsAlgorithm keyAlgorithm, final Parameters parameters)
        {
            final Signer signer;
            final FipsAlgorithm algorithm = getSignatureAlgorithm(keyAlgorithm, parameters);

            switch ((Variations)algorithm.basicVariation())
            {
            case Ed448:
                signer = (parameters instanceof ParametersWithContext) ?
                    edDsaProvider.createEngine(Variations.Ed448, ((ParametersWithContext)parameters).context) :
                    edDsaProvider.createEngine(Variations.Ed448, ZERO_CONTEXT);
                break;
            case Ed448ph:
                signer = (parameters instanceof ParametersWithContext) ?
                    edDsaPhProvider.createEngine(Variations.Ed448ph, ((ParametersWithContext)parameters).context) :
                    edDsaPhProvider.createEngine(Variations.Ed448ph, ZERO_CONTEXT);
                break;
            case Ed25519:
                signer = edDsaProvider.createEngine(Variations.Ed25519, ZERO_CONTEXT);
                break;
            case Ed25519ph:
                signer = (parameters instanceof ParametersWithContext) ?
                    edDsaPhProvider.createEngine(Variations.Ed25519ph, ((ParametersWithContext)parameters).context) :
                    edDsaPhProvider.createEngine(Variations.Ed25519ph, ZERO_CONTEXT);
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }
            return signer;
        }
    }

    private static FipsAlgorithm getSignatureAlgorithm(FipsAlgorithm keyAlg, Parameters parameters)
    {
        if (parameters.getAlgorithm().equals(Algorithm.Pure))
        {
            return (keyAlg.basicVariation() == Variations.Ed448) ? Algorithm.Ed448 : Algorithm.Ed25519;
        }
        else if (parameters.getAlgorithm().equals(Algorithm.Hash))
        {
            return (keyAlg.basicVariation() == Variations.Ed448) ? Algorithm.Ed448ph : Algorithm.Ed25519ph;
        }
        else
        {
            return parameters.getAlgorithm();
        }
    }

    public static byte[] computePublicData(org.bouncycastle.crypto.Algorithm algorithm, byte[] secret)
    {
        byte[] publicKey;

        if (algorithm.equals(FipsEdEC.Algorithm.Ed448) || algorithm.equals(FipsEdEC.Algorithm.Ed448ph))
        {
            final Ed448 ed448 = new Ed448()
            {
                @Override
                protected Xof createXof()
                {
                    return (Xof)FipsSHS.createDigest(FipsSHS.Algorithm.SHAKE256);
                }
            };

            publicKey = new byte[Ed448_PUBLIC_KEY_SIZE];
            ed448.generatePublicKey(secret, 0, publicKey, 0);
        }
        else
        {
            final Ed25519 ed25519 = new Ed25519()
            {
                @Override
                protected Digest createDigest()
                {
                    return FipsSHS.createDigest(FipsSHS.Algorithm.SHA512);
                }
            };

            publicKey = new byte[Ed25519_PUBLIC_KEY_SIZE];
            ed25519.generatePublicKey(secret, 0, publicKey, 0);
        }

        return publicKey;
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricEdDSAPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (privKey.getAlgorithm().equals(Algorithm.Ed448) || privKey.getAlgorithm().equals(Algorithm.Ed448ph))
                {
                    return new Ed448PrivateKeyParameters(privKey.getSecret());
                }
                else
                {
                    return new Ed25519PrivateKeyParameters(privKey.getSecret());
                }
            }
        });
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricEdDSAPublicKey pubKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (pubKey.getAlgorithm().equals(Algorithm.Ed448) || pubKey.getAlgorithm().equals(Algorithm.Ed448ph))
                {
                    return new Ed448PublicKeyParameters(pubKey.getPublicData());
                }
                else
                {
                    return new Ed25519PublicKeyParameters(pubKey.getPublicData());
                }
            }
        });
    }

    private static void validateSigningKeyPair(AsymmetricCipherKeyPair kp)
    {
        if (kp.getPublic() instanceof Ed448PublicKeyParameters)
        {
            SelfTestExecutor.validate(Algorithm.Ed448, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkaySigning(new Ed448Signer(ZERO_CONTEXT), kp);
                }
            });
        }
        else
        {
            SelfTestExecutor.validate(Algorithm.Ed25519, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkaySigning(new Ed25519Signer(), kp);
                }
            });
        }
    }

    private static boolean isOkaySigning(Signer signer, AsymmetricCipherKeyPair kp)
    {
        try
        {
            signer.init(true, kp.getPrivate());

            signer.update(data, 0, data.length);

            byte[] rv = signer.generateSignature();

            signer.init(false, kp.getPublic());

            signer.update(data, 0, data.length);

            return signer.verifySignature(rv);
        }
        catch (Exception e)
        {
            return false;
        }
    }

    private static AsymmetricCipherKeyPair getKATKeys(Variations variation)
    {
        if (variation == Variations.Ed448 || variation == Variations.Ed448ph)
        {
            return new AsymmetricCipherKeyPair(ed448KatPub, ed448KatPriv);
        }
        else
        {
            return new AsymmetricCipherKeyPair(ed25519KatPub, ed25519KatPriv);
        }
    }

    private static class EdDSAProvider
    {
        Signer createEngine(Variations variation, byte[] context)
        {
            return SelfTestExecutor.validate(EdDSA.getAlgorithm(), (variation == Variations.Ed448) ? new Ed448Signer(context) : new Ed25519Signer(), new VariantKatTest<Signer>()
            {
                void evaluate(Signer signer)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeys(variation);

                    signer.init(true, kp.getPrivate());

                    signer.update(data, 0, data.length);

                    byte[] rv = signer.generateSignature();
                    // note: we can only do this for zero length context - if context is specified the signature
                    // value will change and we need to rely on a consistency test.
                    if (context.length == 0)
                    {
                        byte[] expected = (variation == Variations.Ed448) ? katEd448 : katEd25519;
                        if (!Arrays.areEqual(expected, rv))
                        {
                            fail("EdDSAph KAT failed to generate expected signature");
                        }
                    }
                    signer.init(false, kp.getPublic());

                    signer.update(data, 0, data.length);

                    if (!signer.verifySignature(rv))
                    {
                        fail("EdDSA KAT failed to verify");
                    }
                }
            });
        }
    }

    private static class EdDSAphProvider
    {
        Signer createEngine(Variations variation, byte[] context)
        {
            return SelfTestExecutor.validate(EdDSAph.getAlgorithm(), (variation == Variations.Ed448ph) ? new HashEd448Signer(context) : new HashEd25519Signer(context), new VariantKatTest<Signer>()
            {
                void evaluate(Signer signer)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeys(variation);

                    signer.init(true, kp.getPrivate());

                    signer.update(data, 0, data.length);

                    byte[] rv = signer.generateSignature();
                    // note: we can only do this for zero length context - if context is specified the signature
                    // value will change and we need to rely on a consistency test.
                    if (context.length == 0)
                    {
                        byte[] expected = (variation == Variations.Ed448ph) ? katEd448ph : katEd25519ph;
                        if (!Arrays.areEqual(expected, rv))
                        {
                            fail("EdDSAph KAT failed to generate expected signature");
                        }
                    }

                    signer.init(false, kp.getPublic());

                    signer.update(data, 0, data.length);

                    if (!signer.verifySignature(rv))
                    {
                        fail("EdDSAph KAT failed to verify");
                    }
                }
            });
        }
    }
}
