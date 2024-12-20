package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Arrays;

/**
 * Nonce generator for use with AEAD ciphers such as GCM. The generator guarantees the sequence
 * number cannot wrap or go backwards.
 */
public class FipsNonceGenerator
{
    private final byte[] baseNonce;
    private final long counterMask;
    private final int counterBytes;

    private long counterValue;
    private boolean counterExhausted;

    public FipsNonceGenerator(byte[] baseNonce, int counterBits)
    {
        if (baseNonce == null)
        {
            throw new NullPointerException("'baseNonce' cannot be null");
        }
        if (baseNonce.length < 8)
        {
            throw new IllegalArgumentException("'baseNonce' must be at least 8 bytes");
        }
        if (counterBits < 1 || counterBits > 64)
        {
            throw new IllegalArgumentException("'counterBits' must be from 1 to 64 bits");
        }

        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            if (baseNonce.length < 12)
            {
                throw new IllegalArgumentException("Approved mode requires 'baseNonce' of at least 12 bytes");
            }
            if (counterBits < 32)
            {
                throw new IllegalArgumentException("Approved mode requires 'counterBits' of at least 32 bits");
            }
        }

        this.baseNonce = Arrays.clone(baseNonce);
        this.counterMask = -1L >>> (64 - counterBits);
        this.counterBytes = (counterBits + 7) / 8;

        this.counterValue = 0;
        this.counterExhausted = false;
    }

    public void generateNonce(byte[] nonce)
    {
        if (baseNonce.length != nonce.length)
        {
            throw new IllegalArgumentException("'nonce' length must match the base nonce length (" + baseNonce.length + " bytes)");
        }
        if (counterExhausted)
        {
            throw new IllegalStateException("TLS nonce generator exhausted");
        }

        System.arraycopy(baseNonce, 0, nonce, 0, baseNonce.length);
        xorCounter(nonce, baseNonce.length - counterBytes);

        counterExhausted |= ((++counterValue & counterMask) == 0);
    }

    private void xorCounter(byte[] buf, int off)
    {
        for (int i = 0; i < counterBytes; ++i)
        {
            buf[off + i] ^= (byte)(counterValue >>> ((counterBytes - 1 - i) * 8));
        }
    }
}
