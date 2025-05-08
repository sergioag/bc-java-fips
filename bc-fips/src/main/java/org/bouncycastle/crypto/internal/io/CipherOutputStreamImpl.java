package org.bouncycastle.crypto.internal.io;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamException;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.modes.AEADCipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.WrappedByteArrayOutputStream;

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
public abstract class CipherOutputStreamImpl
    extends org.bouncycastle.crypto.CipherOutputStream
{
    protected final String algorithmName;
    protected final boolean isApprovedMode;

    protected OutputStream out;

    protected final byte[] oneByte = new byte[1];

    private static final int INPUT_LEN = 32 * 1024;

    protected CipherOutputStreamImpl(String algorithmName, OutputStream out)
    {
        this.algorithmName = algorithmName;
        this.isApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.out = out;
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

    public static CipherOutputStream getInstance(OutputStream out, StreamCipher cipher)
    {
        if (out instanceof WrappedByteArrayOutputStream)
        {
            return new DirectStreamCipherOutputStream((WrappedByteArrayOutputStream)out, cipher);
        }

        return new StreamCipherOutputStream(out, cipher);
    }

    private static class StreamCipherOutputStream
        extends CipherOutputStreamImpl
    {
        private final StreamCipher streamCipher;
        private final byte[] buf;

        /**
         * Constructs a CipherOutputStream from an OutputStream and a
         * BufferedBlockCipher;.
         */
        public StreamCipherOutputStream(
            OutputStream out,
            StreamCipher cipher)
        {
            super(cipher.getAlgorithmName(), out);
            this.streamCipher = cipher;

            this.buf = new byte[INPUT_LEN];
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

            while (len > 0)
            {
                int outLen = streamCipher.processBytes(b, off, len < INPUT_LEN ? len : INPUT_LEN, buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
                }

                off += INPUT_LEN;
                len -= INPUT_LEN;
            }
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
         * @throws java.io.IOException        if an I/O error occurs.
         * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
         *                                    (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
         */
        public void close()
            throws IOException
        {
            Utils.approvedModeCheck(isApprovedMode, algorithmName);

            IOException error = null;
            try
            {
                streamCipher.reset();
            }
            catch (IllegalStateException e)
            {
                error = new StreamException(e.getMessage(), e.getCause());
            }
            catch (Exception e)
            {
                error = new StreamIOException("Error closing stream: ", e);
            }
            finally
            {
                Arrays.clear(buf);
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

    private static class DirectStreamCipherOutputStream
        extends CipherOutputStreamImpl
    {
        private StreamCipher streamCipher;
        private final WrappedByteArrayOutputStream directOut;

        /**
         * Constructs a CipherOutputStream from an OutputStream and a
         * BufferedBlockCipher;.
         */
        public DirectStreamCipherOutputStream(
            WrappedByteArrayOutputStream out,
            StreamCipher cipher)
        {
            super(cipher.getAlgorithmName(), out);
            this.directOut = out;
            this.streamCipher = cipher;
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

            int outLen = streamCipher.processBytes(b, off, len, directOut.getBuffer(), directOut.getOffset());
            directOut.moveOffset(outLen);
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
         * @throws java.io.IOException        if an I/O error occurs.
         * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
         *                                    (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
         */
        public void close()
            throws IOException
        {
            Utils.approvedModeCheck(isApprovedMode, algorithmName);

            IOException error = null;
            try
            {
                streamCipher.reset();
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

    public static CipherOutputStream getInstance(OutputStream out, BufferedBlockCipher cipher)
    {
        if (out instanceof WrappedByteArrayOutputStream)
        {
            return new DirectBufferedCipherOutputStream((WrappedByteArrayOutputStream)out, cipher);
        }

        return new BufferedCipherOutputStream(out, cipher);
    }

    private static class BufferedCipherOutputStream
        extends CipherOutputStreamImpl
    {
        private final BufferedBlockCipher bufferedBlockCipher;
        private byte[] buf;

        /**
         * Constructs a CipherOutputStream from an OutputStream and a
         * BufferedBlockCipher;.
         */
        public BufferedCipherOutputStream(
            OutputStream out,
            BufferedBlockCipher cipher)
        {
            super(cipher.getUnderlyingCipher().getAlgorithmName(), out);

            this.bufferedBlockCipher = cipher;
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

        /**
         * Ensure the ciphertext buffer has space sufficient to accept an upcoming output.
         *
         * @param updateSize  the size of the pending update.
         * @param finalOutput <code>true</code> iff this the cipher is to be finalised.
         */
        private void ensureCapacity(int updateSize, boolean finalOutput)
        {
            int bufLen;
            if (finalOutput)
            {
                bufLen = bufferedBlockCipher.getOutputSize(updateSize);
            }
            else
            {
                bufLen = bufferedBlockCipher.getUpdateOutputSize(updateSize);
            }

            if (buf == null)
            {
                buf = new byte[bufLen];
            }
            else if (buf.length < bufLen)
            {
                Arrays.clear(buf);
                buf = new byte[bufLen];
            }
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
         * @throws java.io.IOException        if an I/O error occurs.
         * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
         *                                    (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
         */
        public void close()
            throws IOException
        {
            Utils.approvedModeCheck(isApprovedMode, algorithmName);

            ensureCapacity(0, true);
            IOException error = null;
            try
            {
                int outLen = bufferedBlockCipher.doFinal(buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
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
            finally
            {
                if (buf != null)
                {
                    Arrays.clear(buf);
                }
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

    private static class DirectBufferedCipherOutputStream
        extends CipherOutputStreamImpl
    {
        private final BufferedBlockCipher bufferedBlockCipher;
        private final WrappedByteArrayOutputStream directOut;

        /**
         * Constructs a CipherOutputStream from an OutputStream and a
         * BufferedBlockCipher;.
         */
        public DirectBufferedCipherOutputStream(
            WrappedByteArrayOutputStream out,
            BufferedBlockCipher cipher)
        {
            super(cipher.getUnderlyingCipher().getAlgorithmName(), out);

            this.directOut = out;
            this.bufferedBlockCipher = cipher;
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

            int outLen = bufferedBlockCipher.processBytes(b, off, len, directOut.getBuffer(), directOut.getOffset());
            directOut.moveOffset(outLen);
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
         * @throws java.io.IOException        if an I/O error occurs.
         * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
         *                                    (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
         */
        public void close()
            throws IOException
        {
            Utils.approvedModeCheck(isApprovedMode, algorithmName);

            IOException error = null;
            try
            {
                int outLen = bufferedBlockCipher.doFinal(directOut.getBuffer(), directOut.getOffset());
                directOut.moveOffset(outLen);
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

    public static CipherOutputStream getInstance(OutputStream out, AEADCipher cipher)
    {
        if (out instanceof WrappedByteArrayOutputStream)
        {
            return new DirectAEADOutputStream((WrappedByteArrayOutputStream)out, cipher);
        }

        return new AEADOutputStream(out, cipher);
    }

    private static class AEADOutputStream
        extends CipherOutputStreamImpl
    {
        private final AEADCipher aeadBlockCipher;
        private byte[] buf;

        /**
         * Constructs a CipherOutputStream from an OutputStream and a AEADBlockCipher;.
         */
        public AEADOutputStream(OutputStream out, AEADCipher cipher)
        {
            super(cipher.getAlgorithmName(), out);

            this.aeadBlockCipher = cipher;
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

        /**
         * Ensure the ciphertext buffer has space sufficient to accept an upcoming output.
         *
         * @param updateSize  the size of the pending update.
         * @param finalOutput <code>true</code> iff this the cipher is to be finalised.
         */
        private void ensureCapacity(int updateSize, boolean finalOutput)
        {
            int bufLen;
            if (finalOutput)
            {
                bufLen = aeadBlockCipher.getOutputSize(updateSize);
            }
            else
            {
                bufLen = aeadBlockCipher.getUpdateOutputSize(updateSize);
            }

            if (buf == null)
            {
                buf = new byte[bufLen];
            }
            else if (buf.length < bufLen)
            {
                Arrays.clear(buf);
                buf = new byte[bufLen];
            }
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
         * @throws java.io.IOException        if an I/O error occurs.
         * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
         *                                    (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
         */
        public void close()
            throws IOException
        {
            Utils.approvedModeCheck(isApprovedMode, algorithmName);

            ensureCapacity(0, true);
            IOException error = null;
            try
            {
                int outLen = aeadBlockCipher.doFinal(buf, 0);

                if (outLen != 0)
                {
                    out.write(buf, 0, outLen);
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
            finally
            {
                if (buf != null)
                {
                    Arrays.clear(buf);
                }
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

    private static class DirectAEADOutputStream
        extends CipherOutputStreamImpl
    {
        private final AEADCipher aeadBlockCipher;
        private final WrappedByteArrayOutputStream directOut;

        /**
         * Constructs a CipherOutputStream from an OutputStream and a AEADBlockCipher;.
         */
        public DirectAEADOutputStream(WrappedByteArrayOutputStream out, AEADCipher cipher)
        {
            super(cipher.getAlgorithmName(), out);

            this.directOut = out;
            this.aeadBlockCipher = cipher;
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

            int outLen = aeadBlockCipher.processBytes(b, off, len, directOut.getBuffer(), directOut.getOffset());
            directOut.moveOffset(outLen);
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
         * @throws java.io.IOException        if an I/O error occurs.
         * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
         *                                    (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
         */
        public void close()
            throws IOException
        {
            Utils.approvedModeCheck(isApprovedMode, algorithmName);

            IOException error = null;
            try
            {
                int outLen = aeadBlockCipher.doFinal(directOut.getBuffer(), directOut.getOffset());
                directOut.moveOffset(outLen);
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
}
