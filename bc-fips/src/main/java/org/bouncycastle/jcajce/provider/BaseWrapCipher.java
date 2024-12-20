package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.KeyUnwrapper;
import org.bouncycastle.crypto.KeyWrapOperatorFactory;
import org.bouncycastle.crypto.KeyWrapper;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsKeyWrapOperatorFactory;
import org.bouncycastle.util.Arrays;

class BaseWrapCipher
    extends CipherSpi
{
    static class Builder
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private final Algorithm[] algorithms;
        private final Map<Algorithm, Parameters> baseParametersMap;

        private FipsKeyWrapOperatorFactory fipsFactory;
        private KeyWrapOperatorFactory generalFactory;
        private Class[] availableSpecs;

        private int keySizeInBits;
        private ParametersCreatorProvider fipsParametersProvider;
        private ParametersCreatorProvider generalParametersProvider;

        Builder(BouncyCastleFipsProvider fipsProvider, Algorithm... algorithms)
        {
            this.fipsProvider = fipsProvider;
            this.algorithms = algorithms;
            this.baseParametersMap = null;
        }

        Builder(BouncyCastleFipsProvider fipsProvider, Parameters... parameters)
        {
            this.fipsProvider = fipsProvider;
            this.baseParametersMap = new HashMap<Algorithm, Parameters>(parameters.length);
            this.algorithms = new Algorithm[parameters.length];
            for (int i = 0; i != parameters.length; i++)
            {
                this.baseParametersMap.put(parameters[i].getAlgorithm(), parameters[i]);
                this.algorithms[i] = parameters[i].getAlgorithm();
            }
        }

        Builder withFixedKeySize(int keySizeInBits)
        {
            this.keySizeInBits = keySizeInBits;

            return this;
        }

        Builder withFipsOperators(ParametersCreatorProvider fipsParametersProvider, FipsKeyWrapOperatorFactory fipsFactory)
        {
            this.fipsParametersProvider = fipsParametersProvider;
            this.fipsFactory = fipsFactory;

            return this;
        }

        Builder withGeneralOperators(ParametersCreatorProvider generalParametersProvider, KeyWrapOperatorFactory generalFactory)
        {
            this.generalParametersProvider = generalParametersProvider;
            this.generalFactory = generalFactory;

            return this;
        }

        Builder withParameters(Class[] availableSpecs)
        {
            this.availableSpecs = availableSpecs;

            return this;
        }

        BaseWrapCipher build()
        {
            boolean isInApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();

            if (!isInApprovedMode)
            {
                return new BaseWrapCipher(fipsProvider, baseParametersMap, algorithms[0], fipsFactory, generalFactory, availableSpecs, fipsParametersProvider, generalParametersProvider, keySizeInBits);
            }

            Set<Algorithm> activeSet = Utils.getActiveSet(algorithms);

            // no point!
            if (activeSet.isEmpty())
            {
                return null;
            }

            return new BaseWrapCipher(fipsProvider, baseParametersMap, activeSet.toArray(new Algorithm[activeSet.size()])[0], fipsFactory, generalFactory, availableSpecs, fipsParametersProvider, generalParametersProvider, keySizeInBits);
        }
    }

    private final BouncyCastleFipsProvider fipsProvider;

    private AlgorithmParameters     engineParams = null;

    private final Map<Algorithm, Parameters> baseParametersMap;
    private Algorithm                  algorithm;
    private FipsKeyWrapOperatorFactory fipsKeyWrapOperatorFactory;
    private KeyWrapOperatorFactory     generalKeyWrapOperatorFactory;
    private ParametersCreatorProvider fipsParametersProvider;
    private ParametersCreatorProvider generalParametersProvider;
    private Class[]                    availableSpecs;

    private int                       keySizeInBits;
    private Parameters                wrapParameters;
    private KeyWrapper                keyWrapper;
    private KeyUnwrapper              keyUnwrapper;
    private ErasableOutputStream wrapStream = null;

    private BaseWrapCipher(
        BouncyCastleFipsProvider fipsProvider,
        Map<Algorithm, Parameters> baseParametersMap,
        Algorithm algorithm,
        FipsKeyWrapOperatorFactory fipsKeyWrapOperatorFactory,
        KeyWrapOperatorFactory     generalKeyWrapOperatorFactory,
        Class[]                    availableSpecs,
        ParametersCreatorProvider  fipsParametersProvider,
        ParametersCreatorProvider  generalParametersProvider,
        int keySizeInBits)
    {
        this.fipsProvider = fipsProvider;
        this.baseParametersMap = baseParametersMap;
        this.algorithm = algorithm;
        this.fipsKeyWrapOperatorFactory = fipsKeyWrapOperatorFactory;
        this.generalKeyWrapOperatorFactory = generalKeyWrapOperatorFactory;
        this.availableSpecs = availableSpecs;
        this.fipsParametersProvider = fipsParametersProvider;
        this.generalParametersProvider = generalParametersProvider;
        this.keySizeInBits = keySizeInBits;
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected byte[] engineGetIV()
    {
        if (wrapParameters instanceof org.bouncycastle.crypto.ParametersWithIV)
        {
            return ((org.bouncycastle.crypto.ParametersWithIV)wrapParameters).getIV();
        }

        return null;
    }

    protected int engineGetKeySize(
        Key     key)
    {
        return key.getEncoded().length * 8;
    }

    protected int engineGetOutputSize(
        int     inputLen)
    {
        return -1;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (wrapParameters instanceof org.bouncycastle.crypto.ParametersWithIV)
        {
            ParametersWithIV ivParams = (ParametersWithIV)wrapParameters;

            if (ivParams.getIV() != null)
            {
                String  name = Utils.getBaseName(wrapParameters.getAlgorithm());

                try
                {
                    engineParams = AlgorithmParameters.getInstance(name, fipsProvider);

                    engineParams.init(new DEROctetString(ivParams.getIV()).getEncoded());

                    return engineParams;
                }
                catch (Exception e)
                {
                    throw new IllegalStateException(e.toString(), e);
                }
            }
        }

        return null;
    }

    protected void engineSetMode(
        String  mode)
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("Cannot support mode " + mode);
    }

    protected void engineSetPadding(
        String  padding)
    throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("Padding " + padding + " unknown");
    }

    protected void engineInit(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        ParametersCreator parametersCreator = (algorithm instanceof FipsAlgorithm) ? fipsParametersProvider.get(baseParametersMap.get(algorithm)) : generalParametersProvider.get(baseParametersMap.get(algorithm));

        SymmetricKey symmetricKey = new SymmetricSecretKey(algorithm, key.getEncoded());

        if (keySizeInBits != 0 && Utils.keyNotLength(symmetricKey, keySizeInBits))  // restricted key size
        {
            throw new InvalidKeyException("Cipher requires key of size " + keySizeInBits + " bits");
        }

        if (random == null)
        {
            random = fipsProvider.getDefaultSecureRandom();
        }

        wrapStream = null;
        
        try
        {
            switch (opmode)
            {
            case Cipher.ENCRYPT_MODE:
                wrapStream = new ErasableOutputStream();
            case Cipher.WRAP_MODE:
                wrapParameters = parametersCreator.createParameters(true, params, random);

                if (algorithm instanceof FipsAlgorithm)
                {
                    keyWrapper = fipsKeyWrapOperatorFactory.createKeyWrapper(symmetricKey, wrapParameters);
                }
                else
                {
                    keyWrapper = generalKeyWrapOperatorFactory.createKeyWrapper(symmetricKey, wrapParameters);
                }
                keyWrapper = Utils.addRandomIfNeeded(keyWrapper, random);
                keyUnwrapper = null;
                break;
            case Cipher.DECRYPT_MODE:
                wrapStream = new ErasableOutputStream();
            case Cipher.UNWRAP_MODE:
                wrapParameters = parametersCreator.createParameters(false, params, random);

                if (algorithm instanceof FipsAlgorithm)
                {
                    keyUnwrapper = fipsKeyWrapOperatorFactory.createKeyUnwrapper(symmetricKey, wrapParameters);
                }
                else
                {
                    keyUnwrapper = generalKeyWrapOperatorFactory.createKeyUnwrapper(symmetricKey, wrapParameters);
                }
                keyUnwrapper = Utils.addRandomIfNeeded(keyUnwrapper, random);
                keyWrapper = null;
                break;
            default:
                throw new InvalidParameterException("Unknown mode parameter passed to init.");
            }
        }
        catch (InvalidParameterException e)
        {
            throw e;
        }
        catch (IllegalKeyException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
        catch (Exception e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec  paramSpec = null;

        if (params != null)
        {
            for (int i = 0; i != availableSpecs.length; i++)
            {
                try
                {
                    paramSpec = params.getParameterSpec(availableSpecs[i]);
                    break;
                }
                catch (Exception e)
                {
                    // try next spec
                }
            }

            if (paramSpec == null)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }

        engineParams = params;
        engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        SecureRandom        random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        wrapStream.write(input, inputOffset, inputLen);

        return null;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws ShortBufferException
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        wrapStream.write(input, inputOffset, inputLen);

        return 0;
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        if (input != null)
        {
            wrapStream.write(input, inputOffset, inputLen);
        }
        
        try
        {
            if (keyWrapper != null)
            {
                try
                {
                    return keyWrapper.wrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (IllegalArgumentException e)
                {
                    throw new IllegalBlockSizeException(e.getMessage());
                }
                catch (PlainInputProcessingException e)
                {
                    throw new BadPaddingException(e.getMessage());
                }
            }
            else
            {
                try
                {
                    return keyUnwrapper.unwrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (InvalidWrappingException e)
                {
                    throw new BadPaddingException(e.getMessage());
                }
            }
        }
        finally
        {
            wrapStream.erase();
        }
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        wrapStream.write(input, inputOffset, inputLen);

        try
        {
            byte[] enc;

            if (keyWrapper != null)
            {
                try
                {
                    enc = keyWrapper.wrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (IllegalArgumentException e)
                {
                    throw new IllegalBlockSizeException(e.getMessage());
                }
                catch (PlainInputProcessingException e)
                {
                    throw new BadPaddingException(e.getMessage());
                }
            }
            else
            {
                try
                {
                    enc = keyUnwrapper.unwrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (InvalidWrappingException e)
                {
                    throw new BadPaddingException(e.getMessage());
                }
            }

            if (outputOffset + enc.length > output.length)
            {
                throw new ShortBufferException("output buffer too short for input.");
            }

            System.arraycopy(enc, 0, output, outputOffset, enc.length);

            return enc.length;
        }
        finally
        {
            wrapStream.erase();
        }
    }

    protected byte[] engineWrap(
        Key     key)
    throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        try
        {
            return keyWrapper.wrap(encoded, 0, encoded.length);
        }
        catch (PlainInputProcessingException e)
        {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    protected Key engineUnwrap(
        byte[]  wrappedKey,
        String  wrappedKeyAlgorithm,
        int     wrappedKeyType)
    throws InvalidKeyException, NoSuchAlgorithmException
    {
        byte[] encoded;
        try
        {
            encoded = keyUnwrapper.unwrap(wrappedKey, 0, wrappedKey.length);
        }
        catch (Exception e)
        {
            throw new InvalidKeyException(e.getMessage(), e.getCause());
        }

        return rebuildKey(wrappedKeyAlgorithm, wrappedKeyType, encoded, fipsProvider);
    }

    static Key rebuildKey(String wrappedKeyAlgorithm, int wrappedKeyType, byte[] encoded, BouncyCastleFipsProvider fipsProvider)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        if (wrappedKeyType == Cipher.SECRET_KEY)
        {
            return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
        }
        else if (wrappedKeyType == Cipher.PRIVATE_KEY)
        {
            try
            {
                if (wrappedKeyAlgorithm == null || wrappedKeyAlgorithm.equals(""))    // caller doesn't know algorithm
                {
                    PrivateKeyInfo in = PrivateKeyInfo.getInstance(encoded);

                    PrivateKey privKey = fipsProvider.getPrivateKey(in);

                    if (privKey != null)
                    {
                        return privKey;
                    }
                    else
                    {
                        throw new InvalidKeyException("Algorithm " + in.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
                    }
                }
                else
                {
                    KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm, fipsProvider);

                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("Invalid private key encoding: " + e.getMessage(), e);
            }
        }
        else
        {
            try
            {
                if (wrappedKeyAlgorithm == null || wrappedKeyAlgorithm.equals(""))   // caller doesn't know algorithm
                {
                    SubjectPublicKeyInfo in = SubjectPublicKeyInfo.getInstance(encoded);

                    PublicKey pubKey = fipsProvider.getPublicKey(in);

                    if (pubKey != null)
                    {
                        return pubKey;
                    }
                    else
                    {
                        throw new InvalidKeyException("Algorithm " + in.getAlgorithm().getAlgorithm() + " not supported");
                    }
                }
                else
                {
                    KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm, fipsProvider);

                    return kf.generatePublic(new X509EncodedKeySpec(encoded));
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("Invalid private key encoding: " + e.getMessage(), e);
            }
        }
    }

    protected static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }

        public void erase()
        {
            Arrays.fill(this.buf, (byte)0);
            reset();
        }
    }
}
