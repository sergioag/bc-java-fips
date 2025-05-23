package org.bouncycastle.jcajce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SignatureOperatorFactory;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.crypto.general.GeneralAlgorithm;
import org.bouncycastle.crypto.general.RSA;
import org.bouncycastle.jcajce.spec.EdDSASigParameterSpec;

class BaseSignature
    extends SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private static final byte TRAILER_IMPLICIT = (byte)0xBC;

    private final SignatureOperatorFactory operatorFactory;
    private final PublicKeyConverter publicKeyConverter;
    private final PrivateKeyConverter privateKeyConverter;
    private final BouncyCastleFipsProvider fipsProvider;
    private final AlgorithmParameterSpec originalSpec;

    protected Parameters parameters;
    protected OutputVerifier verifier;
    protected OutputSigner signer;
    protected UpdateOutputStream dataStream;

    protected AlgorithmParameters engineParams;
    protected AlgorithmParameterSpec paramSpec;

    protected AsymmetricKey key;
    protected boolean isInitState = true;

    protected BaseSignature(
        BouncyCastleFipsProvider fipsProvider,
        SignatureOperatorFactory operatorFactory,
        PublicKeyConverter publicKeyConverter,
        PrivateKeyConverter privateKeyConverter,
        Parameters parameters)
    {
        this.fipsProvider = fipsProvider;
        this.operatorFactory = operatorFactory;
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
        this.parameters = parameters;
        this.originalSpec = null;
    }

    protected BaseSignature(
        BouncyCastleFipsProvider fipsProvider,
        SignatureOperatorFactory operatorFactory,
        PublicKeyConverter publicKeyConverter,
        PrivateKeyConverter privateKeyConverter,
        Parameters parameters,
        AlgorithmParameterSpec paramSpec)
    {
        this.fipsProvider = fipsProvider;
        this.operatorFactory = operatorFactory;
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
        this.parameters = parameters;
        this.paramSpec = paramSpec;
        this.originalSpec = paramSpec;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        key = publicKeyConverter.convertKey(parameters.getAlgorithm(), publicKey);
        initVerify();
        isInitState = true;
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        key = privateKeyConverter.convertKey(parameters.getAlgorithm(), privateKey);
        initSign(fipsProvider.getDefaultSecureRandom());
        isInitState = true;
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        key = privateKeyConverter.convertKey(parameters.getAlgorithm(), privateKey);
        initSign(random != null ? random : fipsProvider.getDefaultSecureRandom());
        isInitState = true;
    }

    protected void engineUpdate(
        byte b)
        throws SignatureException
    {
        isInitState = false;
        dataStream.update(b);
    }

    protected void engineUpdate(
        byte[] b,
        int off,
        int len)
        throws SignatureException
    {
        isInitState = false;
        dataStream.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            isInitState = true;
            return signer.getSignature();
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString(), e);
        }
    }

    protected boolean engineVerify(
        byte[] sigBytes)
        throws SignatureException
    {
        try
        {
            isInitState = true;
            return verifier.isVerified(sigBytes);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString(), e);
        }
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            if (originalSpec != null)
            {
                params = originalSpec;
            }
            else
            {
                return;
            }
        }

        if (!isInitState)
        {
            throw new ProviderException("cannot call setParameter in the middle of update");
        }

        if (params instanceof PSSParameterSpec)
        {
            PSSParameterSpec newParamSpec = (PSSParameterSpec)params;
            if (originalSpec instanceof PSSParameterSpec)
            {
                PSSParameterSpec origPssSpec = (PSSParameterSpec)originalSpec;

                if (originalSpec != PSSParameterSpec.DEFAULT && !DigestUtil.isSameDigest(origPssSpec.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("Parameter must be using " + origPssSpec.getDigestAlgorithm());
                }
            }

            Algorithm newDigest = DigestUtil.getDigestID(newParamSpec.getDigestAlgorithm());

            String mgfAlgorithm = newParamSpec.getMGFAlgorithm();
            if (!mgfAlgorithm.equalsIgnoreCase("MGF1") && !mgfAlgorithm.equals(PKCSObjectIdentifiers.id_mgf1.getId())
                && !mgfAlgorithm.equalsIgnoreCase("SHAKE128") && !mgfAlgorithm.equals(NISTObjectIdentifiers.id_shake128.getId())
                && !mgfAlgorithm.equalsIgnoreCase("SHAKE256") && !mgfAlgorithm.equals(NISTObjectIdentifiers.id_shake256.getId()))
            {
                throw new InvalidAlgorithmParameterException("Unknown mask generation function specified");
            }

            if (newParamSpec.getMGFParameters() != null && !(newParamSpec.getMGFParameters() instanceof MGF1ParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("Unknown MGF parameters");
            }

            MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)newParamSpec.getMGFParameters();

            Algorithm mgfDigest;
            if (mgfParams != null)
            {
                if (!DigestUtil.isSameDigest(mgfParams.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("Digest algorithm for MGF should be the same as for PSS parameters.");
                }
                mgfDigest = DigestUtil.getDigestID(mgfParams.getDigestAlgorithm());
            }
            else
            {
                mgfDigest = DigestUtil.getDigestID(mgfAlgorithm);
            }

            if (mgfDigest == null)
            {
                throw new InvalidAlgorithmParameterException("No match on MGF digest algorithm: " + mgfParams.getDigestAlgorithm());
            }

            if (mgfDigest instanceof FipsAlgorithm)
            {
                parameters = FipsRSA.PSS.withDigestAlgorithm((FipsDigestAlgorithm)newDigest).withMGFDigest((FipsDigestAlgorithm)mgfDigest).withSaltLength(newParamSpec.getSaltLength()).withTrailer(getPssTrailer(newParamSpec.getTrailerField()));
            }
            else
            {
                throw new InvalidAlgorithmParameterException("Digest algorithm not supported: " + mgfParams.getDigestAlgorithm());
            }
            this.paramSpec = newParamSpec;

            reInit();
        }
        else if (params instanceof EdDSASigParameterSpec)
        {
            Algorithm algorithm = parameters.getAlgorithm();
            if (algorithm == null)
            {
                if (key != null)
                {
                    algorithm = key.getAlgorithm();
                }
            }
            // TODO: prehash needs to be accounted for later
            if (algorithm != null)
            {
                if (((EdDSASigParameterSpec)params).getContext() != null)
                {
                    paramSpec = params;
                    parameters = new FipsEdEC.ParametersWithContext((FipsAlgorithm)algorithm, ((EdDSASigParameterSpec)params).getContext());
                    reInit();
                }
            }
            else
            {
                throw new InvalidAlgorithmParameterException("cannot identify algorithm, call initSign/initVerify first");
            }
        }
        else
        {
            if (parameters instanceof RSA.PSSSignatureParameters
                || parameters instanceof FipsRSA.PSSSignatureParameters)
            {
                throw new InvalidAlgorithmParameterException("only PSSParameterSpec supported");
            }

            throw new InvalidAlgorithmParameterException("unknown AlgorithmParameterSpec in signature");
        }
    }

    private void reInit()
        throws InvalidAlgorithmParameterException
    {
        if (key instanceof AsymmetricPublicKey)
        {
            initVerify();
        }
        else if (key instanceof AsymmetricPrivateKey)
        {
            try
            {
                initSign(appRandom);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidAlgorithmParameterException("parameter inappropriate for key:" + e.getMessage());
            }
        }
    }

    private void initVerify()
    {
        verifier = operatorFactory.createVerifier((AsymmetricPublicKey)key, parameters);
        dataStream = verifier.getVerifyingStream();
    }

    private void initSign(SecureRandom random)
        throws InvalidKeyException
    {
        this.appRandom = random;
        try
        {
            // TODO: should change addRandomIfNeeded in 1.1 (maybe? - it's correct in this case but is it always?
            signer = Utils.addRandomIfNeeded(operatorFactory.createSigner((AsymmetricPrivateKey)key, parameters), random);
            dataStream = signer.getSigningStream();
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("cannot initialize for signing: " + e.getMessage(), e);
        }
    }

    private byte getPssTrailer(
        int trailerField)
    {
        if (trailerField == 1)
        {
            return TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("unknown trailer field");
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = AlgorithmParameters.getInstance("PSS", fipsProvider);
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new IllegalStateException(e.toString(), e);
                }
            }
        }

        return engineParams;
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
     */
    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("SetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#engineGetParameters()">engineGetParameters()</a>
     */
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("GetParameter unsupported");
    }
}
