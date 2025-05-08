package org.bouncycastle.crypto.general;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputValidator;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;
import org.bouncycastle.crypto.internal.pqc.lms.DigestProvider;
import org.bouncycastle.crypto.internal.pqc.lms.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.internal.pqc.lms.HSSKeyPairGenerator;
import org.bouncycastle.crypto.internal.pqc.lms.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.HSSPublicKeyParameters;
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

public class LMS
{
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("LMS");

    public static final Parameters SIG = new Parameters(ALGORITHM);

    public static final OTSParameters sha256_n32_w1 = new OTSParameters(LMOtsParameters.sha256_n32_w1);
    public static final OTSParameters sha256_n32_w2 = new OTSParameters(LMOtsParameters.sha256_n32_w2);
    public static final OTSParameters sha256_n32_w4 = new OTSParameters(LMOtsParameters.sha256_n32_w4);
    public static final OTSParameters sha256_n32_w8 = new OTSParameters(LMOtsParameters.sha256_n32_w8);

    public static final KeyParameters lms_sha256_n32_h5 = new KeyParameters(LMSigParameters.lms_sha256_n32_h5);
    public static final KeyParameters lms_sha256_n32_h10 = new KeyParameters(LMSigParameters.lms_sha256_n32_h10);
    public static final KeyParameters lms_sha256_n32_h15 = new KeyParameters(LMSigParameters.lms_sha256_n32_h15);
    public static final KeyParameters lms_sha256_n32_h20 = new KeyParameters(LMSigParameters.lms_sha256_n32_h20);
    public static final KeyParameters lms_sha256_n32_h25 = new KeyParameters(LMSigParameters.lms_sha256_n32_h25);

    static
    {
        LmsDigestUtil.setProvider(new LmsDigestProvider());
    }

    public static final class Parameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        Parameters(GeneralAlgorithm algorithm)
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
        extends GeneralParameters<GeneralAlgorithm>
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
        extends GeneralParameters<GeneralAlgorithm>
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
        extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricLMSPublicKey, AsymmetricLMSPrivateKey>
    {
        private AsymmetricCipherKeyPairGenerator engine;

        public KeyPairGenerator(KeyGenParameters parameters, SecureRandom random)
        {
            super(parameters);

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
        protected AsymmetricKeyPair<AsymmetricLMSPublicKey, AsymmetricLMSPrivateKey> doGenerateKeyPair()
        {
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
        extends GuardedSignatureOperatorFactory<Parameters>
    {
        public OperatorFactory()
        {
        }

        @Override
        protected OutputSigner<Parameters> doCreateSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final LMSContextBasedSigner signer = ((AsymmetricLMSPrivateKey)key).getContextBasedSigner();

            return new OutputSigner<Parameters>()
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
        protected OutputVerifier<Parameters> doCreateVerifier(AsymmetricPublicKey key, final Parameters parameters)
        {
            final LMSContextBasedVerifier verifier = ((AsymmetricLMSPublicKey)key).getContextBasedVerifier();

            return new OutputVerifier<Parameters>()
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

        protected OutputValidator<Parameters> doCreateValidator(AsymmetricPublicKey key, final Parameters parameters, final byte[] signature)
            throws InvalidSignatureException
        {
            final LMSContextBasedVerifier verifier = ((AsymmetricLMSPublicKey)key).getContextBasedVerifier();

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

            return new OutputValidator<Parameters>()
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
                return (Digest)FipsRegister.getProvider(FipsSHS.Algorithm.SHA256).createEngine();
            }
            if (digOid.equals(NISTObjectIdentifiers.id_sha512))
            {
                return (Digest)FipsRegister.getProvider(FipsSHS.Algorithm.SHA512).createEngine();
            }
            if (digOid.equals(NISTObjectIdentifiers.id_shake128))
            {
                return (Digest)FipsRegister.getProvider(FipsSHS.Algorithm.SHAKE128).createEngine();
            }
            if (digOid.equals(NISTObjectIdentifiers.id_shake256) || digOid.equals(NISTObjectIdentifiers.id_shake256_len))
            {
                return (Digest)FipsRegister.getProvider(FipsSHS.Algorithm.SHAKE256).createEngine();
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
}
