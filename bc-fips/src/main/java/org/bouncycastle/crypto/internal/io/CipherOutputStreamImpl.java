package org.bouncycastle.crypto.internal.io;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamException;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.modes.AEADCipher;

/**
 * A CipherOutputStream is composed of an OutputStream and a cipher so that write() methods process
 * the written data with the cipher, and the output of the cipher is in turn written to the
 * underlying OutputStream. The cipher must be fully initialized before being used by a
 * CipherInputStream.
 * <p>
 * For example, if the cipher is initialized for encryption, the CipherOutputStream will encrypt the
 * data before writing the encrypted data to the underlying stream.
 * </p>
 * <p>
 * Note: this class does not close the underlying stream on a close.
 * </p>
 */
public class CipherOutputStreamImpl
    extends org.bouncycastle.crypto.CipherOutputStream
{
    private final String algorithmName;
    private final boolean isApprovedMode;

    private OutputStream out;
    private BufferedBlockCipher bufferedBlockCipher;
    private StreamCipher streamCipher;
    private AEADCipher aeadBlockCipher;

    private final byte[] oneByte = new byte[1];
    private byte[] buf;

    private static final int INPUT_LEN = 4 * 1024;

    /**
     * Constructs a CipherOutputStream from an OutputStream and a
     * BufferedBlockCipher;.
     */
    public CipherOutputStreamImpl(
        OutputStream out,
        BufferedBlockCipher cipher)
    {
        this.isApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithmName = cipher.getUnderlyingCipher().getAlgorithmName();
        this.out = out;
        this.bufferedBlockCipher = cipher;
    }

    /**
     * Constructs a CipherOutputStream from an OutputStream and a
     * BufferedBlockCipher;.
     */
    public CipherOutputStreamImpl(
        OutputStream out,
        StreamCipher cipher)
    {
        this.isApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithmName = cipher.getAlgorithmName();
        this.out = out;
        this.streamCipher = cipher;
    }

    /**
     * Constructs a CipherOutputStream from an OutputStream and a AEADBlockCipher;.
     */
    public CipherOutputStreamImpl(OutputStream out, AEADCipher cipher)
    {
        this.isApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithmName = cipher.getAlgorithmName();
        this.out = out;
        this.aeadBlockCipher = cipher;
    }

    /**
     * Writes the specified byte to this output stream.
     *
     * @param b the <code>byte</code>.
     * @throws java.io.IOException if an I/O error occurs.
     */
    public void write(
        int b)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        oneByte[0] = (byte)b;

        write(oneByte, 0, 1);
    }

    /**
     * Writes <code>b.length</code> bytes from the specified byte array
     * to this output stream.
     * <p>
     * The <code>write</code> method of
     * <code>CipherOutputStream</code> calls the <code>write</code>
     * method of three arguments with the three arguments
     * <code>b</code>, <code>0</code>, and <code>b.length</code>.
     *
     * @param b the data.
     * @throws java.io.IOException if an I/O error occurs.
     * @see #write(byte[], int, int)
     */
    public void write(
        byte[] b)
        throws IOException
    {
        write(b, 0, b.length);
    }

    /**
     * Writes <code>len</code> bytes from the specified byte array
     * starting at offset <code>off</code> to this output stream.
     *
     * @param b   the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     * @throws java.io.IOException if an I/O error occurs.
     */
    public void write(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        if (bufferedBlockCipher != null)
        {
            while (len > 0)
            {
                ensureCapacity(INPUT_LEN, false);

                int outLen = bufferedBlockCipher.processBytes(b, off, len < INPUT_LEN ? len : INPUT_LEN, buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
                }

                off += INPUT_LEN;
                len -= INPUT_LEN;
            }
        }
        else if (aeadBlockCipher != null)
        {
            while (len > 0)
            {
                ensureCapacity(INPUT_LEN, false);

                int outLen = aeadBlockCipher.processBytes(b, off, len < INPUT_LEN ? len : INPUT_LEN, buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
                }

                off += INPUT_LEN;
                len -= INPUT_LEN;
            }
        }
        else
        {
            while (len > 0)
            {
                ensureCapacity(INPUT_LEN, false);

                int outLen = streamCipher.processBytes(b, off, len < INPUT_LEN ? len : INPUT_LEN, buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
                }

                off += INPUT_LEN;
                len -= INPUT_LEN;
            }
        }
    }

    /**
     * Ensure the ciphertext buffer has space sufficient to accept an upcoming output.
     *
     * @param updateSize the size of the pending update.
     * @param finalOutput <code>true</code> iff this the cipher is to be finalised.
     */
    private void ensureCapacity(int updateSize, boolean finalOutput)
    {
        int bufLen = updateSize;
        if (finalOutput)
        {
            if (bufferedBlockCipher != null)
            {
                bufLen = bufferedBlockCipher.getOutputSize(updateSize);
            }
            else if (aeadBlockCipher != null)
            {
                bufLen = aeadBlockCipher.getOutputSize(updateSize);
            }
        }
        else
        {
            if (bufferedBlockCipher != null)
            {
                bufLen = bufferedBlockCipher.getUpdateOutputSize(updateSize);
            }
            else if (aeadBlockCipher != null)
            {
                bufLen = aeadBlockCipher.getUpdateOutputSize(updateSize);
            }
        }

        if ((buf == null) || (buf.length < bufLen))
        {
            buf = new byte[bufLen];
        }
    }

    /**
     * Flushes this output stream by forcing any buffered output bytes
     * that have already been processed by the encapsulated cipher object
     * to be written out.
     * <p>
     * Any bytes buffered by the encapsulated cipher
     * and waiting to be processed by it will not be written out. For example,
     * if the encapsulated cipher is a block cipher, and the total number of
     * bytes written using one of the <code>write</code> methods is less than
     * the cipher's block size, no bytes will be written out.
     *
     * @throws java.io.IOException if an I/O error occurs.
     */
    public void flush()
        throws IOException
    {
        out.flush();
    }

    /**
     * Closes this output stream and releases any system resources
     * associated with this stream.
     * <p>
     * This method invokes the <code>doFinal</code> method of the encapsulated
     * cipher object, which causes any bytes buffered by the encapsulated
     * cipher to be processed. The result is written out by calling the
     * <code>flush</code> method of this output stream.
     * <p>
     * This method resets the encapsulated cipher object to its initial state
     * and does not call <code>close</code> method of the underlying output
     * stream.
     *
     * @throws java.io.IOException if an I/O error occurs.
     * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
     * (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
     */
    public void close()
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        ensureCapacity(0, true);
        IOException error = null;
        try
        {
            if (bufferedBlockCipher != null)
            {
                int outLen = bufferedBlockCipher.doFinal(buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
                }
            }
            else if (aeadBlockCipher != null)
            {
                int outLen = aeadBlockCipher.doFinal(buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
                }
            }
            else if (streamCipher != null)
            {
                streamCipher.reset();
            }
        }
        catch (org.bouncycastle.crypto.internal.InvalidCipherTextException e)
        {
            error = new InvalidCipherTextException("Error finalising cipher data: " + e.getMessage(), e);
        }
        catch (IllegalStateException e)
        {
            error = new StreamException(e.getMessage(), e.getCause());
        }
        catch (Exception e)
        {
            error = new StreamIOException("Error closing stream: ", e);
        }

        try
        {
            flush();
        }
        catch (IOException e)
        {
            // Invalid ciphertext takes precedence over close error
            if (error == null)
            {
                error = e;
            }
        }
        if (error != null)
        {
            throw error;
        }
    }
}