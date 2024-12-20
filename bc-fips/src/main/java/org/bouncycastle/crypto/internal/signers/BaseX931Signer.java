package org.bouncycastle.crypto.internal.signers;

import java.math.BigInteger;

import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.CryptoException;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.params.RsaKeyParameters;
import org.bouncycastle.crypto.internal.util.ISOTrailers;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * X9.31-1998 - signing using a hash.
 * <p>
 * The message digest hash, H, is encapsulated to form a byte string as follows
 * <pre>
 * EB = 06 || PS || 0xBA || H || TRAILER
 * </pre>
 * where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|, and TRAILER is the ISO/IEC 10118 part number† for the digest. The byte string, EB, is converted to an integer value, the message representative, f.
 */
public class BaseX931Signer
    implements Signer
{
    static final public int   TRAILER_IMPLICIT    = 0xBC;

    private Digest                      digest;
    private AsymmetricBlockCipher       cipher;
    private RsaKeyParameters            kParam;

    private int         trailer;
    private int         keyBits;
    private byte[]      block;

    /**
     * Generate a signer with either implicit or explicit trailers for X9.31
     *
     * @param cipher base cipher to use for signature creation/verification
     * @param digest digest to use.
     * @param implicit whether or not the trailer is implicit or gives the hash.
     */
    public BaseX931Signer(
        AsymmetricBlockCipher cipher,
        Digest digest,
        boolean implicit)
    {
        this.cipher = cipher;
        this.digest = digest;

        if (implicit)
        {
            trailer = TRAILER_IMPLICIT;
        }
        else
        {
            Integer trailerObj = ISOTrailers.getTrailer(digest);

            if (trailerObj != null)
            {
                trailer = trailerObj.intValue();
            }
            else
            {
                throw new IllegalArgumentException("no valid trailer for digest: " + digest.getAlgorithmName());
            }
        }
    }
    
    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        if (param instanceof ParametersWithRandom)
        {
            kParam = (RsaKeyParameters)((ParametersWithRandom)param).getParameters();
        }
        else
        {
            kParam = (RsaKeyParameters)param;
        }

        cipher.init(forSigning, param);

        keyBits = kParam.getModulus().bitLength();

        block = new byte[(keyBits + 7) / 8];

        reset();
    }
    
    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        digest.update(b);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        digest.update(in, off, len);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
    }

    /**
     * generate a signature for the loaded message using the key we were
     * initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException
    {
        createSignatureBlock(trailer);

        BigInteger t = new BigInteger(1, cipher.processBlock(block, 0, block.length));
        clearBlock(block);

        t = t.min(kParam.getModulus().subtract(t));

        return BigIntegers.asUnsignedByteArray((kParam.getModulus().bitLength() + 7) / 8, t);
    }

    private void createSignatureBlock(int trailer)
    {
        int     digSize = digest.getDigestSize();

        int delta;

        if (trailer == TRAILER_IMPLICIT)
        {
            delta = block.length - digSize - 1;
            digest.doFinal(block, delta);
            block[block.length - 1] = (byte)TRAILER_IMPLICIT;
        }
        else
        {
            delta = block.length - digSize - 2;
            digest.doFinal(block, delta);
            block[block.length - 2] = (byte)(trailer >>> 8);
            block[block.length - 1] = (byte)trailer;
        }

        block[0] = 0x6b;
        for (int i = delta - 2; i != 0; i--)
        {
            block[i] = (byte)0xbb;
        }
        block[delta - 1] = (byte)0xba;
    }

    /**
     * return true if the signature represents a X9.31 signature
     * for the passed in message.
     */
    public boolean verifySignature(
        byte[]      signature)
    {
        try
        {
            block = cipher.processBlock(signature, 0, signature.length);
        }
        catch (Exception e)
        {
            return false;
        }

        BigInteger t = new BigInteger(1, block);
        BigInteger f;

        if ((t.intValue() & 15) == 12)
        {
             f = t;
        }
        else
        {
            t = kParam.getModulus().subtract(t);
            if ((t.intValue() & 15) == 12)
            {
                 f = t;
            }
            else
            {
                return false;
            }
        }

        createSignatureBlock(trailer);

        byte[] fBlock = BigIntegers.asUnsignedByteArray(block.length, f);

        boolean rv = Arrays.constantTimeAreEqual(block, fBlock);

        // check for old NIST tool value
        if (trailer == ISOTrailers.TRAILER_SHA512_256 && !rv)
        {
            block[block.length - 2] = (byte)0x40;   // old NIST CAVP tool value
            rv = Arrays.constantTimeAreEqual(block, fBlock);
        }
        
        clearBlock(block);
        clearBlock(fBlock);

        return rv;
    }
}
