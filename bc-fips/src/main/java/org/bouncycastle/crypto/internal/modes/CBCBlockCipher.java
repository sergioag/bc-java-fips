/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.modes;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
 */
public class CBCBlockCipher
    implements BlockCipher
{
    private byte[] IV;
    private byte[] cbcV;
    private byte[] cbcNextV;

    private int blockSize;
    private BlockCipher cipher = null;
    private boolean encrypting;

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of chaining.
     */
    public CBCBlockCipher(
        BlockCipher cipher)
    {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();

        this.IV = new byte[blockSize];
        this.cbcV = new byte[blockSize];
        this.cbcNextV = new byte[blockSize];
    }

    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     *
     * @param encrypting if true the cipher is initialised for
     *                   encryption, if false for decryption.
     * @param params     the key and other data required by the cipher.
     * @throws IllegalArgumentException if the params argument is
     *                                  inappropriate.
     */
    public void init(
        boolean encrypting,
        CipherParameters params)
        throws IllegalArgumentException
    {
        boolean oldEncrypting = this.encrypting;

        this.encrypting = encrypting;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();

            if (iv.length != blockSize)
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }

            System.arraycopy(iv, 0, IV, 0, iv.length);

            reset();

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(encrypting, ivParam.getParameters());
            }
            else if (oldEncrypting != encrypting)
            {
                throw new IllegalArgumentException("cannot change encrypting state without providing key.");
            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(encrypting, params);
            }
            else if (oldEncrypting != encrypting)
            {
                throw new IllegalArgumentException("cannot change encrypting state without providing key.");
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/CBC".
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/CBC";
    }

    /**
     * return the block size of the underlying cipher.
     *
     * @return the block size of the underlying cipher.
     */
    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param in     the array containing the input data.
     * @param inOff  offset into the in array the data starts at.
     * @param out    the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @return the number of bytes processed and produced.
     * @throws DataLengthException   if there isn't enough data in in, or
     *                               space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException
    {
        return (encrypting) ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        System.arraycopy(IV, 0, cbcV, 0, IV.length);
        Arrays.fill(cbcNextV, (byte)0);

        cipher.reset();
    }

    /**
     * Do the appropriate chaining step for CBC mode encryption.
     *
     * @param in     the array containing the data to be encrypted.
     * @param inOff  offset into the in array the data starts at.
     * @param out    the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @return the number of bytes processed and produced.
     * @throws DataLengthException   if there isn't enough data in in, or
     *                               space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    private int encryptBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException
    {
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        /*
         * XOR the cbcV and the input,
         * then encrypt the cbcV
         */
        for (int i = 0; i < blockSize; i++)
        {
            cbcV[i] ^= in[inOff + i];
        }

        int length = cipher.processBlock(cbcV, 0, out, outOff);

        /*
         * copy ciphertext to cbcV
         */
        System.arraycopy(out, outOff, cbcV, 0, cbcV.length);

        return length;
    }

    /**
     * Do the appropriate chaining step for CBC mode decryption.
     *
     * @param in     the array containing the data to be decrypted.
     * @param inOff  offset into the in array the data starts at.
     * @param out    the array the decrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @return the number of bytes processed and produced.
     * @throws DataLengthException   if there isn't enough data in in, or
     *                               space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    private int decryptBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException
    {
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        System.arraycopy(in, inOff, cbcNextV, 0, blockSize);

        int length = cipher.processBlock(in, inOff, out, outOff);

        /*
         * XOR the cbcV and the output
         */
        for (int i = 0; i < blockSize; i++)
        {
            out[outOff + i] ^= cbcV[i];
        }

        /*
         * swap the back up buffer into next position
         */
        byte[] tmp;

        tmp = cbcV;
        cbcV = cbcNextV;
        cbcNextV = tmp;

        return length;
    }

    @Override
    public String toString()
    {
        return "CBC[Java](" + cipher.toString() + ")";
    }
}
