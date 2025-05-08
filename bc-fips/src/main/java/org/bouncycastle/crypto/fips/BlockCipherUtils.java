package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.internal.DefaultBufferedMultiBlockCipher;
import org.bouncycastle.crypto.internal.EngineProvider;
import org.bouncycastle.crypto.internal.MultiBlockCipher;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.modes.CBCBlockCipher;
import org.bouncycastle.crypto.internal.modes.CCMBlockCipher;
import org.bouncycastle.crypto.internal.modes.CFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.GCMBlockCipher;
import org.bouncycastle.crypto.internal.modes.NISTCTSBlockCipher;
import org.bouncycastle.crypto.internal.modes.OFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.SICBlockCipher;
import org.bouncycastle.crypto.internal.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.internal.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.internal.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.internal.paddings.PKCS7Padding;
import org.bouncycastle.crypto.internal.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.internal.paddings.PaddedBufferedMultiBlockCipher;
import org.bouncycastle.crypto.internal.paddings.TBCPadding;
import org.bouncycastle.crypto.internal.paddings.X923Padding;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class BlockCipherUtils
{
    private static SecureRandom defaultRandomPadder;

    static BufferedBlockCipher createBlockCipher(EngineProvider<MultiBlockCipher> provider, FipsParameters parameter)
    {
        Mode mode = ((Mode)parameter.getAlgorithm().basicVariation());
        Padding padding = (Padding)parameter.getAlgorithm().additionalVariation();

        BlockCipher cipher = null;

        if (provider == FipsAES.ENGINE_PROVIDER)
        {
            if (mode == Mode.CFB128 && NativeLoader.hasNativeService(FipsNativeServices.AES_CFB))
            {
                //
                // Standalone CFB128 implementation
                //
                cipher = AESNativeCFB.newInstance();
            }
            else if (mode == Mode.CBC &&
                padding != Padding.CS1 &&
                padding != Padding.CS2 &&
                padding != Padding.CS3 &&
                NativeLoader.hasNativeService(FipsNativeServices.AES_CBC))
            {
                //
                // Standalone Hardware CBC implementation
                //
                cipher = AESNativeCBC.newInstance();
            }
            else if (mode == Mode.CTR &&
                NativeLoader.hasNativeService(FipsNativeServices.AES_CTR))
            {
                cipher = AESNativeCTR.newInstance();
            }
        }

        if (cipher == null)
        {
            //
            // Transformations that build on ECB
            //
            cipher = provider.createEngine();
            switch (((Mode)parameter.getAlgorithm().basicVariation()))
            {
            case ECB:
                break;
            case CBC:
                if (padding != Padding.CS1 && padding != Padding.CS2 && padding != Padding.CS3)
                {
                    cipher = new CBCBlockCipher(cipher);
                }
                break;
            case CFB8:
                cipher = new CFBBlockCipher(cipher, 8);
                break;
            case CFB64:
                cipher = new CFBBlockCipher(cipher, 64);
                break;
            case CFB128:
                cipher = new CFBBlockCipher(cipher, 128);
                break;
            case OFB64:
                cipher = new OFBBlockCipher(cipher, 64);
                break;
            case OFB128:
                cipher = new OFBBlockCipher(cipher, 128);
                break;
            case CTR:
                cipher = new SICBlockCipher(cipher);
                break;
            default:
                throw new IllegalArgumentException("Unknown mode passed to createBlockCipher: " + parameter.getAlgorithm());
            }
        }

        if (padding != null)
        {
            switch (padding)
            {
            case PKCS7:
                return makePadded(cipher, new PKCS7Padding());
            case ISO7816_4:
                return makePadded(cipher, new ISO7816d4Padding());
            case ISO10126_2:
                return makePadded(cipher, new ISO10126d2Padding());
            case TBC:
                return makePadded(cipher, new TBCPadding());
            case X923:
                return makePadded(cipher, new X923Padding());
            case CS1:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS1, cipher);
            case CS2:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS2, cipher);
            case CS3:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS3, cipher);
            default:
                throw new IllegalArgumentException("Unknown padding passed to createBlockCipher: " + parameter.getAlgorithm());
            }
        }

        if (cipher instanceof MultiBlockCipher)
        {
            return new DefaultBufferedMultiBlockCipher((MultiBlockCipher)cipher);
        }

        return new DefaultBufferedBlockCipher(cipher);
    }


    static BufferedBlockCipher makePadded(BlockCipher cipher, BlockCipherPadding padding)
    {
        if (cipher instanceof MultiBlockCipher)
        {
            return new PaddedBufferedMultiBlockCipher((MultiBlockCipher)cipher, padding);
        }
        return new PaddedBufferedBlockCipher(cipher, padding);
    }

    static BufferedBlockCipher createStandardCipher(boolean forEncryption, final ValidatedSymmetricKey key, EngineProvider<MultiBlockCipher> engineProvider, Parameters parameters, SecureRandom random)
    {
        BufferedBlockCipher cipher = BlockCipherUtils.createBlockCipher(engineProvider, (FipsParameters)parameters);
        CipherParameters cipherParameters = Utils.getKeyParameter(key);

        if (parameters instanceof ParametersWithIV)
        {
            byte[] iv = ((ParametersWithIV)parameters).getIV();

            if (iv != null)
            {
                cipherParameters = new org.bouncycastle.crypto.internal.params.ParametersWithIV(cipherParameters, iv);
            }
        }

        if (((FipsAlgorithm)parameters.getAlgorithm()).additionalVariation() instanceof Padding)
        {
            Padding padding = (Padding)((FipsAlgorithm)parameters.getAlgorithm()).additionalVariation();

            if (padding.getBasePadding().requiresRandom() && forEncryption)
            {
                if (random != null)
                {
                    cipherParameters = new ParametersWithRandom(cipherParameters, random);
                }
                else
                {
                    try
                    {
                        cipherParameters = new ParametersWithRandom(cipherParameters, CryptoServicesRegistrar.getSecureRandom());
                    }
                    catch (IllegalStateException e)
                    {
                        cipherParameters = new ParametersWithRandom(cipherParameters, getDefaultRandomPadder());
                    }
                }
            }
        }

        cipher.init(forEncryption, cipherParameters);

        return cipher;
    }

    static AEADBlockCipher createAEADCipher(FipsAlgorithm algorithm, EngineProvider<MultiBlockCipher> provider)
    {
        AEADBlockCipher cipher;

        switch (((Mode)algorithm.basicVariation()))
        {
        case CCM:
            cipher = new CCMBlockCipher(provider.createEngine());
            break;
        case GCM:
            if (NativeLoader.hasNativeService(FipsNativeServices.AES_GCM))
            {
                cipher = AESNativeGCM.newInstance();
            }
            else
            {
                cipher = new GCMBlockCipher(provider.createEngine());
            }
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to createAEADCipher: " + algorithm);
        }

        return cipher;
    }

    static synchronized SecureRandom getDefaultRandomPadder()
    {
        if (defaultRandomPadder == null)
        {
            defaultRandomPadder = FipsDRBG.SHA512.fromDefaultEntropy().
                setPersonalizationString(Strings.toByteArray("Bouncy Castle FIPS Default Padder"))
                .build(Pack.longToBigEndian(System.currentTimeMillis()), false);
        }

        return defaultRandomPadder;
    }
}
