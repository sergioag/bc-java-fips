package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;

class Ed25519Signer
    implements Signer
{
    private final Buffer buffer = new Buffer();

    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public Ed25519Signer()
    {
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;

        if (forSigning)
        {
            this.privateKey = (Ed25519PrivateKeyParameters)parameters;
            this.publicKey = null;
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters)parameters;
        }

        reset();
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        buffer.write(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed25519Signer not initialised for signature generation.");
        }

        return buffer.generateSignature(privateKey);
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed25519Signer not initialised for verification");
        }

        return buffer.verifySignature(publicKey, signature);
    }

    public void reset()
    {
        buffer.reset();
    }

    private static class Buffer
        extends ByteArrayOutputStream
    {
        private final Ed25519 ed25519 = new Ed25519()
        {
            @Override
            protected Digest createDigest()
            {
                return FipsSHS.createDigest(FipsSHS.Algorithm.SHA512);
            }
        };

        synchronized byte[] generateSignature(Ed25519PrivateKeyParameters privateKey)
        {
            byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
            privateKey.sign(Ed25519.Algorithm.Ed25519, null, buf, 0, count, signature, 0);
            reset();
            return signature;
        }

        synchronized boolean verifySignature(Ed25519PublicKeyParameters publicKey, byte[] signature)
        {
            if (Ed25519.SIGNATURE_SIZE != signature.length)
            {
                reset();
                return false;
            }

            byte[] pk = publicKey.getEncoded();
            boolean result = ed25519.verify(signature, 0, pk, 0, buf, 0, count);
            reset();
            return result;
        }

        public synchronized void reset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            this.count = 0;
        }
    }
}
