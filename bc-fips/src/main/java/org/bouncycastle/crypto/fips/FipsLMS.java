package org.bouncycastle.crypto.fips;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;
import org.bouncycastle.crypto.internal.pqc.lms.DigestProvider;
import org.bouncycastle.crypto.internal.pqc.lms.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.internal.pqc.lms.HSSKeyPairGenerator;
import org.bouncycastle.crypto.internal.pqc.lms.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.HSSPublicKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.HSSSigner;
import org.bouncycastle.crypto.internal.pqc.lms.LMOtsParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSContext;
import org.bouncycastle.crypto.internal.pqc.lms.LMSContextBasedSigner;
import org.bouncycastle.crypto.internal.pqc.lms.LMSContextBasedVerifier;
import org.bouncycastle.crypto.internal.pqc.lms.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSKeyPairGenerator;
import org.bouncycastle.crypto.internal.pqc.lms.LMSParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSPublicKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSigParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LmsDigestUtil;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class FipsLMS
{
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("LMS");

    public static final Parameters SIG = new Parameters(ALGORITHM);

    public static final OTSParameters sha256_n32_w1 = new OTSParameters(LMOtsParameters.sha256_n32_w1);
    public static final OTSParameters sha256_n32_w2 = new OTSParameters(LMOtsParameters.sha256_n32_w2);
    public static final OTSParameters sha256_n32_w4 = new OTSParameters(LMOtsParameters.sha256_n32_w4);
    public static final OTSParameters sha256_n32_w8 = new OTSParameters(LMOtsParameters.sha256_n32_w8);
    public static final OTSParameters sha256_n24_w1 = new OTSParameters(LMOtsParameters.sha256_n24_w1);
    public static final OTSParameters sha256_n24_w2 = new OTSParameters(LMOtsParameters.sha256_n24_w2);
    public static final OTSParameters sha256_n24_w4 = new OTSParameters(LMOtsParameters.sha256_n24_w4);
    public static final OTSParameters sha256_n24_w8 = new OTSParameters(LMOtsParameters.sha256_n24_w8);

    public static final OTSParameters shake256_n32_w1 = new OTSParameters(LMOtsParameters.shake256_n32_w1);
    public static final OTSParameters shake256_n32_w2 = new OTSParameters(LMOtsParameters.shake256_n32_w2);
    public static final OTSParameters shake256_n32_w4 = new OTSParameters(LMOtsParameters.shake256_n32_w4);
    public static final OTSParameters shake256_n32_w8 = new OTSParameters(LMOtsParameters.shake256_n32_w8);
    public static final OTSParameters shake256_n24_w1 = new OTSParameters(LMOtsParameters.shake256_n24_w1);
    public static final OTSParameters shake256_n24_w2 = new OTSParameters(LMOtsParameters.shake256_n24_w2);
    public static final OTSParameters shake256_n24_w4 = new OTSParameters(LMOtsParameters.shake256_n24_w4);
    public static final OTSParameters shake256_n24_w8 = new OTSParameters(LMOtsParameters.shake256_n24_w8);

    public static final KeyParameters lms_sha256_n32_h5 = new KeyParameters(LMSigParameters.lms_sha256_n32_h5);
    public static final KeyParameters lms_sha256_n32_h10 = new KeyParameters(LMSigParameters.lms_sha256_n32_h10);
    public static final KeyParameters lms_sha256_n32_h15 = new KeyParameters(LMSigParameters.lms_sha256_n32_h15);
    public static final KeyParameters lms_sha256_n32_h20 = new KeyParameters(LMSigParameters.lms_sha256_n32_h20);
    public static final KeyParameters lms_sha256_n32_h25 = new KeyParameters(LMSigParameters.lms_sha256_n32_h25);

    public static final KeyParameters lms_sha256_n24_h5 = new KeyParameters(LMSigParameters.lms_sha256_n24_h5);
    public static final KeyParameters lms_sha256_n24_h10 = new KeyParameters(LMSigParameters.lms_sha256_n24_h10);
    public static final KeyParameters lms_sha256_n24_h15 = new KeyParameters(LMSigParameters.lms_sha256_n24_h15);
    public static final KeyParameters lms_sha256_n24_h20 = new KeyParameters(LMSigParameters.lms_sha256_n24_h20);
    public static final KeyParameters lms_sha256_n24_h25 = new KeyParameters(LMSigParameters.lms_sha256_n24_h25);
    
    public static final KeyParameters lms_shake256_n32_h5 = new KeyParameters(LMSigParameters.lms_shake256_n32_h5);
    public static final KeyParameters lms_shake256_n32_h10 = new KeyParameters(LMSigParameters.lms_shake256_n32_h10);
    public static final KeyParameters lms_shake256_n32_h15 = new KeyParameters(LMSigParameters.lms_shake256_n32_h15);
    public static final KeyParameters lms_shake256_n32_h20 = new KeyParameters(LMSigParameters.lms_shake256_n32_h20);
    public static final KeyParameters lms_shake256_n32_h25 = new KeyParameters(LMSigParameters.lms_shake256_n32_h25);
    
    public static final KeyParameters lms_shake256_n24_h5 = new KeyParameters(LMSigParameters.lms_shake256_n24_h5);
    public static final KeyParameters lms_shake256_n24_h10 = new KeyParameters(LMSigParameters.lms_shake256_n24_h10);
    public static final KeyParameters lms_shake256_n24_h15 = new KeyParameters(LMSigParameters.lms_shake256_n24_h15);
    public static final KeyParameters lms_shake256_n24_h20 = new KeyParameters(LMSigParameters.lms_shake256_n24_h20);
    public static final KeyParameters lms_shake256_n24_h25 = new KeyParameters(LMSigParameters.lms_shake256_n24_h25);

    private static final byte[] castHssPub = Base64.decode("MEgwDQYLKoZIhvcNAQkQAxEDNwAENAAAAAIAAAAKAAAAB2cDIrkJ5u/LECpGllUHqBkXyZbRZswV95KkHoXKPvfguGrriD/xzqU=");
    private static final byte[] castMsg = Hex.decode("48656c6c6f2c20776f726c6421");
    private static final byte[] castSig = Base64.decode("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");

    static
    {
        LmsDigestUtil.setProvider(new LmsDigestProvider());

        // FSM_STATE:5.LMS.0,"LMS SIGN VERIFY KAT", "The module is performing LMS verify KAT self-test"
        // FSM_TRANS:5.LMS.0.0,"CONDITIONAL TEST","LMS SIGN VERIFY KAT", "Invoke LMS Verify KAT self-test"
        lmsStartUpTest();
        // FSM_TRANS:5.LMS.0.1,"LMS SIGN VERIFY KAT","CONDITIONAL TEST", "LMS Verify KAT self-test successful completion"
        // FSM_TRANS:5.LMS.0.2,"LMS SIGN VERIFY KAT","SOFT ERROR", "LMS  Verify KAT self-test failed"
    }

    public static final class Parameters
        extends FipsParameters
    {
        Parameters(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    public static final class OTSParameters
    {
        private final LMOtsParameters otsParameters;

        OTSParameters(LMOtsParameters sigParameters)
        {
            this.otsParameters = sigParameters;
        }
    }

    public static final class KeyParameters
        extends FipsParameters
    {
        private final LMSigParameters sigParams;
        private final LMOtsParameters otsParams;

        private KeyParameters(LMSigParameters sigParams, LMOtsParameters otsParams)
        {
            super(ALGORITHM);
            this.sigParams = sigParams;
            this.otsParams = otsParams;
        }

        KeyParameters(LMSigParameters sigParams)
        {
            this(sigParams, sha256_n32_w4.otsParameters);
        }

        public KeyParameters using(OTSParameters otsParameters)
        {
            return new KeyParameters(this.sigParams, otsParameters.otsParameters);
        }
    }

    /**
     * Parameters for LMS/HSS key pair generation.
     */
    public static final class KeyGenParameters
        extends FipsParameters
    {
        private final KeyParameters[] keyParameters;

        public KeyGenParameters(KeyParameters... keyParameters)
        {
            super(ALGORITHM);
            if (keyParameters.length == 0)
            {
                throw new IllegalArgumentException("at least one keyParameter required");
            }
            this.keyParameters = keyParameters;
        }
    }

    public static final class KeyPairGenerator
        extends FipsAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricLMSPublicKey, AsymmetricLMSPrivateKey>
    {
        private AsymmetricCipherKeyPairGenerator engine;

        public KeyPairGenerator(KeyGenParameters parameters, SecureRandom random)
        {
            super(parameters);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new UnsupportedOperationException("LMS keypair generation not available in approved mode");
            }

            KeyParameters[] keyParams = parameters.keyParameters;
            if (keyParams.length == 1)
            {
                LMSKeyGenerationParameters param = new LMSKeyGenerationParameters(
                    new LMSParameters(keyParams[0].sigParams, keyParams[0].otsParams), random);

                engine = new LMSKeyPairGenerator();
                engine.init(param);
            }
            else
            {
                LMSParameters[] hssParams = new LMSParameters[keyParams.length];
                for (int i = 0; i != keyParams.length; i++)
                {
                    hssParams[i] = new LMSParameters(keyParams[i].sigParams, keyParams[i].otsParams);
                }
                HSSKeyGenerationParameters param = new HSSKeyGenerationParameters(hssParams, random);

                engine = new HSSKeyPairGenerator();
                engine.init(param);
            }
        }

        @Override
        public AsymmetricKeyPair<AsymmetricLMSPublicKey, AsymmetricLMSPrivateKey> generateKeyPair()
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new UnsupportedOperationException("LMS key pair generation not available in approved mode");
            }

            AsymmetricCipherKeyPair pair = engine.generateKeyPair();

            if (engine instanceof LMSKeyPairGenerator)
            {
                LMSPublicKeyParameters pub = (LMSPublicKeyParameters)pair.getPublic();
                LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters)pair.getPrivate();

                return new AsymmetricKeyPair(new AsymmetricLMSPublicKey(1, pub.getEncoded()), new AsymmetricLMSPrivateKey(1, priv.getEncoded(), pub.getEncoded()));
            }
            else
            {
                HSSPublicKeyParameters pub = (HSSPublicKeyParameters)pair.getPublic();
                HSSPrivateKeyParameters priv = (HSSPrivateKeyParameters)pair.getPrivate();

                return new AsymmetricKeyPair(new AsymmetricLMSPublicKey(pub.getL(), pub.getLMSPublicKey().getEncoded()), new AsymmetricLMSPrivateKey(priv.getL(), priv.getEncoded(), pub.getLMSPublicKey().getEncoded()));
            }
        }
    }

    /**
     * Operator factory for creating LMS based signing and verification operators.
     */
    public static final class OperatorFactory
        extends FipsSignatureOperatorFactory<Parameters>
    {
        public OperatorFactory()
        {
        }

        @Override
        public FipsOutputSigner<Parameters> createSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final LMSContextBasedSigner signer = ((AsymmetricLMSPrivateKey)key).getContextBasedSigner();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new UnsupportedOperationException("LMS signature generation not available in approved mode");
            }

            return new FipsOutputSigner<Parameters>()
            {
                final LMSContext lmsContext = signer.generateLMSContext();

                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getSigningStream()
                {
                    return new DigestOutputStream(lmsContext);
                }

                public byte[] getSignature()
                    throws PlainInputProcessingException
                {
                    byte[] sig = signer.generateSignature(lmsContext);

                    return sig;
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
            final LMSContextBasedVerifier verifier = ((AsymmetricLMSPublicKey)key).getContextBasedVerifier();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new UnsupportedOperationException("LMS signature verification not available in approved mode");
            }

            return new FipsOutputVerifier<Parameters>()
            {
                final ByteArrayUpdateOutputStream bOut = new ByteArrayUpdateOutputStream();

                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getVerifyingStream()
                {
                    return bOut;
                }

                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    LMSContext lmsContext;
                    try
                    {
                        lmsContext = verifier.generateLMSContext(signature);
                    }
                    catch (InvalidSignatureException e)
                    {
                        throw e;
                    }
                    catch (IOException e)
                    {
                        throw new InvalidSignatureException("exception parsing signature: " + e.getMessage(), e);
                    }

                    bOut.outputTo(lmsContext);

                    return verifier.verify(lmsContext);
                }
            };
        }

        public FipsOutputValidator<Parameters> createValidator(AsymmetricPublicKey key, final Parameters parameters, final byte[] signature)
            throws InvalidSignatureException
        {
            final LMSContextBasedVerifier verifier = ((AsymmetricLMSPublicKey)key).getContextBasedVerifier();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new UnsupportedOperationException("LMS signature validation not available in approved mode");
            }

            final LMSContext lmsContext;
            try
            {
                lmsContext = verifier.generateLMSContext(signature);
            }
            catch (InvalidSignatureException e)
            {
                throw e;
            }
            catch (IOException e)
            {
                throw new InvalidSignatureException("exception parsing signature: " + e.getMessage(), e);
            }

            return new FipsOutputValidator<Parameters>()
            {
                final DigestOutputStream dOut = new DigestOutputStream(lmsContext);

                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getValidatingStream()
                {
                    return dOut;
                }

                public boolean isValidated()
                {
                    return verifier.verify(lmsContext);
                }
            };
        }
    }

    private static class LmsDigestProvider
        implements DigestProvider
    {
        public Digest getDigest(ASN1ObjectIdentifier digOid)
        {
            if (digOid.equals(NISTObjectIdentifiers.id_sha256))
            {
                return FipsSHS.createDigest(FipsSHS.Algorithm.SHA256);
            }
            if (digOid.equals(NISTObjectIdentifiers.id_sha512))
            {
                return FipsSHS.createDigest(FipsSHS.Algorithm.SHA512);
            }
            if (digOid.equals(NISTObjectIdentifiers.id_shake128))
            {
                return FipsSHS.createDigest(FipsSHS.Algorithm.SHAKE128);
            }
            if (digOid.equals(NISTObjectIdentifiers.id_shake256) || digOid.equals(NISTObjectIdentifiers.id_shake256_len))
            {
                return FipsSHS.createDigest(FipsSHS.Algorithm.SHAKE256);
            }

            throw new IllegalArgumentException("unrecognized digest OID: " + digOid);
        }
    }

    private static class ByteArrayUpdateOutputStream
        extends UpdateOutputStream
    {
        ExposedByteArrayOutputStream exOut = new ExposedByteArrayOutputStream();

        public void write(byte[] in, int inOff, int inLen)
        {
            exOut.write(in, inOff, inLen);
        }

        @Override
        public void write(int i)
            throws IOException
        {
            exOut.write(i);
        }

        void outputTo(Digest digest)
        {
            exOut.outputTo(digest);
            exOut.reset();
        }
    }

    private static class ExposedByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        void outputTo(Digest digest)
        {
            digest.update(this.buf, 0, this.count);
        }
    }

    private static void lmsStartUpTest()
    {
        SelfTestExecutor.validate(FipsLMS.ALGORITHM, new HSSSigner(), new BasicKatTest<HSSSigner>()
        {
            @Override
            public boolean hasTestPassed(HSSSigner engine)
                throws Exception
            {
                AsymmetricLMSPublicKey pubKey = new AsymmetricLMSPublicKey(castHssPub);

                engine.init(false, (CipherParameters)pubKey.getContextBasedVerifier());
                
                return engine.verifySignature(castMsg, castSig);
            }
        });

    }

}
