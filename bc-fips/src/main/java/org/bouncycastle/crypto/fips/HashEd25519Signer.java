package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

class HashEd25519Signer
    implements Signer
{
    private final Ed25519 ed25519 = new Ed25519()
    {
        @Override
        protected Digest createDigest()
        {
            return FipsSHS.createDigest(FipsSHS.Algorithm.SHA512);
        }
    };
    private final Digest prehash = ed25519.createPrehash();
    private final byte[] context;

    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public HashEd25519Signer(byte[] context)
    {
        if (null == context)
        {
            throw new NullPointerException("'context' cannot be null");
        }

        this.context = Arrays.clone(context);
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
        prehash.update(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        prehash.update(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed25519phSigner not initialised for signature generation.");
        }

        byte[] msg = new byte[Ed25519.PREHASH_SIZE];
        if (Ed25519.PREHASH_SIZE != prehash.doFinal(msg, 0))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
        privateKey.sign(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PREHASH_SIZE, signature, 0);
        return signature;
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed25519phSigner not initialised for verification");
        }
        if (Ed25519.SIGNATURE_SIZE != signature.length)
        {
            prehash.reset();
            return false;
        }

        byte[] msg = new byte[Ed25519.PREHASH_SIZE];
        if (Ed25519.PREHASH_SIZE != prehash.doFinal(msg, 0))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        return publicKey.verify(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PREHASH_SIZE, signature, 0);
    }

    public void reset()
    {
        prehash.reset();
    }
}
