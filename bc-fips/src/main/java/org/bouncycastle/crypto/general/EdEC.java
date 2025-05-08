package org.bouncycastle.crypto.general;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Agreement;
import org.bouncycastle.crypto.AgreementFactory;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputValidator;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPublicKey;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.fips.FipsOutputSigner;
import org.bouncycastle.crypto.fips.FipsOutputValidator;
import org.bouncycastle.crypto.fips.FipsOutputVerifier;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.RawAgreement;
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
public final class EdEC
{
    public static final byte[] ZERO_CONTEXT = new byte[0];

    private EdEC()
    {

    }

    public static final class Algorithm
    {
        private Algorithm()
        {

        }

        public static final GeneralAlgorithm Ed448 = new GeneralAlgorithm("Ed448", Variations.Ed448);
        public static final GeneralAlgorithm Ed25519 = new GeneralAlgorithm("Ed25519", Variations.Ed25519);

        public static final GeneralAlgorithm X448 = new GeneralAlgorithm("X448", Variations.X448);
        public static final GeneralAlgorithm X25519 = new GeneralAlgorithm("X25519", Variations.X25519);
    }

    public static final Parameters EdDSA = new Parameters(null);
    public static final Parameters Ed448 = new Parameters(Algorithm.Ed448);
    public static final Parameters Ed25519 = new Parameters(Algorithm.Ed25519);

    public static final Parameters X448 = new Parameters(Algorithm.X448);
    public static final Parameters X25519 = new Parameters(Algorithm.X25519);

    private enum Variations
    {
        Ed448,
        Ed25519,
        X448,
        X25519
    }

    public static final int X448_PUBLIC_KEY_SIZE = X448PublicKeyParameters.KEY_SIZE;
    public static final int X25519_PUBLIC_KEY_SIZE = X25519PublicKeyParameters.KEY_SIZE;
    public static final int Ed448_PUBLIC_KEY_SIZE = FipsEdEC.Ed448_PUBLIC_KEY_SIZE;
    public static final int Ed25519_PUBLIC_KEY_SIZE = FipsEdEC.Ed25519_PUBLIC_KEY_SIZE;

    public static final int X448_PRIVATE_KEY_SIZE = X448PrivateKeyParameters.KEY_SIZE;
    public static final int X25519_PRIVATE_KEY_SIZE = X25519PrivateKeyParameters.KEY_SIZE;
    public static final int Ed448_PRIVATE_KEY_SIZE = FipsEdEC.Ed448_PRIVATE_KEY_SIZE;
    public static final int Ed25519_PRIVATE_KEY_SIZE = FipsEdEC.Ed25519_PRIVATE_KEY_SIZE;

    /**
     * Edwards Curve key pair generation parameters.
     */
    public static class Parameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        /**
         * Base constructor.
         *
         * @param algorithm the EdEC domain parameters algorithm.
         */
        Parameters(GeneralAlgorithm algorithm)
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
        public ParametersWithContext(GeneralAlgorithm algorithm, byte[] context)
        {
            super(algorithm);
            if (!algorithm.equals(Algorithm.Ed448))
            {
                throw new IllegalArgumentException("context can only be used with Ed448");
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
        extends GuardedAsymmetricKeyPairGenerator
    {
        private final FipsEdEC.EdDSAKeyPairGenerator kpGenerator;

        public EdDSAKeyPairGenerator(Parameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            FipsEdEC.Parameters fipsParams;

            switch ((Variations)keyGenParameters.getAlgorithm().basicVariation())
            {
            case Ed448:
                fipsParams = FipsEdEC.Ed448;
                break;
            case Ed25519:
                fipsParams = FipsEdEC.Ed25519;
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            this.kpGenerator = new FipsEdEC.EdDSAKeyPairGenerator(fipsParams, random);
        }

        @Override
        protected AsymmetricKeyPair doGenerateKeyPair()
        {
            return kpGenerator.generateKeyPair();
        }
    }

    /**
     * Edwards Curve Diffie-Hellman key pair generator.
     */
    public static final class XDHKeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator
    {
        private final Variations variation;
        private final AsymmetricCipherKeyPairGenerator kpGen;

        public XDHKeyPairGenerator(Parameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            switch ((Variations)keyGenParameters.getAlgorithm().basicVariation())
            {
            case X448:
                this.variation = Variations.X448;
                this.kpGen = new X448KeyPairGenerator();
                break;
            case X25519:
                this.variation = Variations.X25519;
                this.kpGen = new X25519KeyPairGenerator();
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            kpGen.init(new KeyGenerationParameters(random, 0));    // strength ignored
        }

        @Override
        protected AsymmetricKeyPair doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            validateAgreementKeyPair(kp);

            switch (variation)
            {
            case X448:
                return new AsymmetricKeyPair(
                    new AsymmetricXDHPublicKey(getParameters().getAlgorithm(), ((X448PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricXDHPrivateKey(getParameters().getAlgorithm(), ((X448PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((X448PublicKeyParameters)kp.getPublic()).getEncoded()));
            case X25519:
                return new AsymmetricKeyPair(
                    new AsymmetricXDHPublicKey(getParameters().getAlgorithm(), ((X25519PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricXDHPrivateKey(getParameters().getAlgorithm(), ((X25519PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((X25519PublicKeyParameters)kp.getPublic()).getEncoded()));
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }
        }
    }

    /**
     * Operator factory for creating Edwards Curve DSA based signing and verification operators.
     */
    public static final class EdDSAOperatorFactory
        extends GuardedSignatureOperatorFactory<Parameters>
    {
        final FipsEdEC.EdDSAOperatorFactory opFact;

        public EdDSAOperatorFactory()
        {
            opFact = new FipsEdEC.EdDSAOperatorFactory();
        }

        @Override
        protected OutputSigner<Parameters> doCreateSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final FipsEdEC.Parameters fipsParams = toFipsParams(key, parameters);

            final FipsOutputSigner signer = opFact.createSigner(key, fipsParams);

            return new OutputSigner<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getSigningStream()
                {
                    return signer.getSigningStream();
                }

                public byte[] getSignature()
                    throws PlainInputProcessingException
                {
                    return signer.getSignature();
                }

                public int getSignature(byte[] output, int off)
                    throws PlainInputProcessingException
                {
                    return signer.getSignature(output, off);
                }
            };
        }

        @Override
        protected OutputVerifier<Parameters> doCreateVerifier(AsymmetricPublicKey key, final Parameters parameters)
        {
            final FipsEdEC.Parameters fipsParams = toFipsParams(key, parameters);

            final FipsOutputVerifier verifier = opFact.createVerifier(key, fipsParams);

            return new OutputVerifier<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getVerifyingStream()
                {
                    return verifier.getVerifyingStream();
                }

                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    return verifier.isVerified(signature);
                }
            };
        }

        @Override
        protected OutputValidator<Parameters> doCreateValidator(AsymmetricPublicKey key, final Parameters parameters, final byte[] signature)
        {
            final FipsEdEC.Parameters fipsParams = toFipsParams(key, parameters);

            final FipsOutputValidator validator = opFact.createValidator(key, fipsParams, signature);

            return new OutputValidator<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getValidatingStream()
                {
                    return validator.getValidatingStream();
                }

                public boolean isValidated()
                {
                    return validator.isValidated();
                }
            };
        }

        private FipsEdEC.Parameters toFipsParams(AsymmetricKey key, Parameters parameters)
        {
            final GeneralAlgorithm algorithm = (parameters.getAlgorithm() != null) ? parameters.getAlgorithm() : (GeneralAlgorithm)key.getAlgorithm();
            final FipsEdEC.Parameters fipsParams;

            switch ((Variations)algorithm.basicVariation())
            {
            case Ed448:
                fipsParams = (parameters instanceof ParametersWithContext) ?
                    new FipsEdEC.ParametersWithContext(FipsEdEC.Algorithm.Ed448, ((ParametersWithContext)parameters).context) :
                    FipsEdEC.Ed448;
                break;
            case Ed25519:
                fipsParams = (parameters instanceof ParametersWithContext) ?
                    new FipsEdEC.ParametersWithContext(FipsEdEC.Algorithm.Ed25519, ((ParametersWithContext)parameters).context) :
                    FipsEdEC.Ed25519;
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }
            return fipsParams;
        }
    }

    /**
     * Factory for Agreement operators based on Edwards Curve Diffie-Hellman.
     */
    public static final class XDHAgreementFactory
        implements AgreementFactory<Parameters>
    {
        public XDHAgreementFactory()
        {
            FipsStatus.isReady();
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
            }
        }

        public Agreement<Parameters> createAgreement(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final RawAgreement agreement;

            switch ((Variations)parameters.getAlgorithm().basicVariation())
            {
            case X448:
                agreement = new X448Agreement();

                agreement.init(getLwKey((AsymmetricXDHPrivateKey)key));
                break;
            case X25519:
                agreement = new X25519Agreement();

                agreement.init(getLwKey((AsymmetricXDHPrivateKey)key));
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            return new Agreement<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricKeyParameter lwKey = getLwKey((AsymmetricXDHPublicKey)key);
                    byte[] sharedValue;

                    if (lwKey instanceof X448PublicKeyParameters)
                    {
                        sharedValue = new byte[X448PrivateKeyParameters.SECRET_SIZE];
                    }
                    else
                    {
                        sharedValue = new byte[X25519PrivateKeyParameters.SECRET_SIZE];
                    }

                    agreement.calculateAgreement(lwKey, sharedValue, 0);

                    return sharedValue;
                }
            };
        }
    }

    public static byte[] computePublicData(org.bouncycastle.crypto.Algorithm algorithm, byte[] secret)
    {
        byte[] publicKey;

        if (algorithm.equals(FipsEdEC.Algorithm.Ed448))
        {
            final Ed448 ed448 = new Ed448()
            {
                @Override
                protected Xof createXof()
                {
                    return (Xof)Register.createDigest(FipsSHS.Algorithm.SHAKE256);
                }
            };

            publicKey = new byte[Ed448_PUBLIC_KEY_SIZE];
            ed448.generatePublicKey(secret, 0, publicKey, 0);
        }
        else if (algorithm.equals(FipsEdEC.Algorithm.Ed25519))
        {
            final Ed25519 ed25519 = new Ed25519()
            {
                @Override
                protected Digest createDigest()
                {
                    return Register.createDigest(FipsSHS.Algorithm.SHA512);
                }
            };

            publicKey = new byte[Ed25519_PUBLIC_KEY_SIZE];
            ed25519.generatePublicKey(secret, 0, publicKey, 0);
        }
        else if (algorithm.equals(EdEC.Algorithm.X448))
        {
            publicKey = new byte[X448_PUBLIC_KEY_SIZE];
            org.bouncycastle.math.ec.rfc7748.X448.generatePublicKey(secret, 0, publicKey, 0);
        }
        else
        {
            publicKey = new byte[X25519_PUBLIC_KEY_SIZE];
            org.bouncycastle.math.ec.rfc7748.X25519.generatePublicKey(secret, 0, publicKey, 0);
        }

        return publicKey;
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricXDHPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (privKey.getAlgorithm().equals(Algorithm.X448))
                {
                    return new X448PrivateKeyParameters(privKey.getSecret());
                }
                else
                {
                    return new X25519PrivateKeyParameters(privKey.getSecret());
                }
            }
        });
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricXDHPublicKey pubKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (pubKey.getAlgorithm().equals(Algorithm.X448))
                {
                    return new X448PublicKeyParameters(pubKey.getPublicData());
                }
                else
                {
                    return new X25519PublicKeyParameters(pubKey.getPublicData());
                }
            }
        });
    }

    private static final byte[] x448Secret = Hex.decode("683ea9b2857ff88fff5160bede45edb3b64f5d76c2c3ef6ef0479caa65c6ec2bcddaf76e3c3c61dcc557a09771b7593cf6240c2328b4054f");
    private static final byte[] x448Public = Hex.decode("daafe9ae6984c3ab2fea0498990ee3c1690aac801e508a735e037436dcd16435c5fa93b5186e668247c4c1e9560a3d2e53a1136ca714978b");

    private static final byte[] x25519Secret = Hex.decode("4a434deaa453db96d893c92d4193d5ccb0002e74121548f936c2a313b9fd3a49");
    private static final byte[] x25519Public = Hex.decode("722143ed71a72fb2f6ecb3a2549d09d0e9db308b79450c38cd2d406ef8723167");

    private static void validateAgreementKeyPair(AsymmetricCipherKeyPair kp)
    {
        if (kp.getPublic() instanceof X448PublicKeyParameters)
        {
            SelfTestExecutor.validate(Algorithm.X448, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkayAgreeing(new X448Agreement(), kp, new X448PrivateKeyParameters(x448Secret), new X448PublicKeyParameters(x448Public));
                }
            });
        }
        else
        {
            SelfTestExecutor.validate(Algorithm.X25519, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkayAgreeing(new X25519Agreement(), kp, new X25519PrivateKeyParameters(x25519Secret), new X25519PublicKeyParameters(x25519Public));
                }
            });
        }
    }

    private static boolean isOkayAgreeing(RawAgreement agreement, AsymmetricCipherKeyPair kp,
                                          CipherParameters testPriv, CipherParameters testPub)
    {
        try
        {
            byte[] rv1 = new byte[agreement.getAgreementSize()];
            byte[] rv2 = new byte[agreement.getAgreementSize()];

            agreement.init(kp.getPrivate());

            agreement.calculateAgreement(testPub, rv1, 0);

            agreement.init(testPriv);

            agreement.calculateAgreement(kp.getPublic(), rv2, 0);

            return Arrays.areEqual(rv1, rv2);
        }
        catch (Exception e)
        {
            return false;
        }
    }
}
