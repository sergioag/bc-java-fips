package org.bouncycastle.crypto.general;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.AEADOperatorFactory;
import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InputAEADDecryptor;
import org.bouncycastle.crypto.OutputAEADDecryptor;
import org.bouncycastle.crypto.OutputAEADEncryptor;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.io.CipherInputStream;
import org.bouncycastle.crypto.internal.io.CipherOutputStreamImpl;
import org.bouncycastle.crypto.internal.modes.AEADCipher;

abstract class GuardedAEADOperatorFactory<T extends Parameters>
    implements AEADOperatorFactory<T>
{
    // package protect construction
    GuardedAEADOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode.");
        }
    }

    public OutputAEADEncryptor<T> createOutputAEADEncryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return new OutEncryptor(key, parameters);
    }

    public InputAEADDecryptor<T> createInputAEADDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        final AEADCipher cipher = createAEADCipher(false, key, parameters);

        return new InputAEADDecryptor<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public UpdateOutputStream getAADStream()
            {
                return new AADStream(cipher);
            }

            public InputStream getDecryptingStream(InputStream in)
            {
                return new CipherInputStream(in, cipher);
            }

            public byte[] getMAC()
            {
                return cipher.getMac();
            }
        };
    }

    public OutputAEADDecryptor<T> createOutputAEADDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        final AEADCipher cipher = createAEADCipher(false, key, parameters);

        return new OutputAEADDecryptor<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return cipher.getOutputSize(inputLen);
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return cipher.getUpdateOutputSize(inputLen);
            }

            public UpdateOutputStream getAADStream()
            {
                return new AADStream(cipher);
            }

            public org.bouncycastle.crypto.CipherOutputStream getDecryptingStream(final OutputStream out)
            {
                return CipherOutputStreamImpl.getInstance(out, cipher);
            }

            public byte[] getMAC()
            {
                return cipher.getMac();
            }
        };
    }

    abstract protected AEADCipher createAEADCipher(boolean forEncryption, SymmetricKey key, T parameters);

    private class OutEncryptor
        implements OutputAEADEncryptor<T>
    {
        private final T parameters;
        private final AEADCipher cipher;

        OutEncryptor(SymmetricKey key, T parameters)
        {
            this.parameters = parameters;
            this.cipher = createAEADCipher(true, key, parameters);
        }

        public T getParameters()
        {
            return parameters;
        }

        public int getMaxOutputSize(int inputLen)
        {
            return cipher.getOutputSize(inputLen);
        }

        public int getUpdateOutputSize(int inputLen)
        {
            return cipher.getUpdateOutputSize(inputLen);
        }

        public UpdateOutputStream getAADStream()
        {
            return new AADStream(cipher);
        }

        public CipherOutputStream getEncryptingStream(final OutputStream out)
        {
            return CipherOutputStreamImpl.getInstance(out, cipher);
        }

        public byte[] getMAC()
        {
            return cipher.getMac();
        }
    }

    private class AADStream
        extends UpdateOutputStream
    {
        private AEADCipher cipher;

        AADStream(AEADCipher cipher)
        {
            this.cipher = cipher;
        }

        @Override
        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            cipher.processAADBytes(buf, off, len);
        }

        @Override
        public void write(int b)
            throws IOException
        {
            cipher.processAADByte((byte)b);
        }
    }
}
