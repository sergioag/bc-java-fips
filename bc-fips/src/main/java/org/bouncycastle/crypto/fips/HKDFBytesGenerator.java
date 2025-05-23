package org.bouncycastle.crypto.fips;


import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.DerivationFunction;
import org.bouncycastle.crypto.internal.DerivationParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.params.HKDFParameters;

/**
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
 * according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
 * Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
 * (output keying material) and is likely to have better security properties
 * than KDF's based on just a hash function.
 */
class HKDFBytesGenerator
    implements DerivationFunction
{
    private HMac hMacHash;
    private int hashLen;

    private byte[] info;
    private byte[] currentT;

    private int generatedBytes;

    /**
     * Creates a HKDFBytesGenerator based on the given hash function.
     *
     * @param hash the digest to be used as the source of generatedBytes bytes
     */
    public HKDFBytesGenerator(Digest hash)
    {
        this.hMacHash = new HMac(hash);
        this.hashLen = hash.getDigestSize();
    }

    public HKDFBytesGenerator(HMac hMac)
    {
        this.hMacHash = hMac;
        this.hashLen = hMac.getUnderlyingDigest().getDigestSize();
    }

    public void init(DerivationParameters param)
    {
        if (!(param instanceof HKDFParameters))
        {
            throw new IllegalArgumentException(
                "HKDF parameters required for HKDFBytesGenerator");
        }

        HKDFParameters params = (HKDFParameters)param;

        hMacHash.init(params.getKey());

        info = params.getInfo();

        generatedBytes = 0;
        currentT = new byte[hashLen];
    }

    /**
     * Performs the expand part of the key derivation function, using currentT
     * as input and output buffer.
     *
     * @throws DataLengthException if the total number of bytes generated is larger than the one
     *                             specified by RFC 5869 (255 * HashLen)
     */
    private void expandNext()
        throws DataLengthException
    {
        int n = generatedBytes / hashLen + 1;
        if (n >= 256)
        {
            throw new DataLengthException(
                "HKDF cannot generate more than 255 blocks of HashLen size");
        }
        // special case for T(0): T(0) is empty, so no update
        if (generatedBytes != 0)
        {
            hMacHash.update(currentT, 0, hashLen);
        }
        hMacHash.update(info, 0, info.length);
        hMacHash.update((byte)n);
        hMacHash.doFinal(currentT, 0);
    }

    public Digest getDigest()
    {
        return hMacHash.getUnderlyingDigest();
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {

        if (generatedBytes + len > 255 * hashLen)
        {
            throw new DataLengthException(
                "HKDF may only be used for 255 * HashLen bytes of output");
        }

        if (generatedBytes % hashLen == 0)
        {
            expandNext();
        }

        // copy what is left in the currentT (1..hash
        int toGenerate = len;
        int posInT = generatedBytes % hashLen;
        int leftInT = hashLen - generatedBytes % hashLen;
        int toCopy = Math.min(leftInT, toGenerate);
        System.arraycopy(currentT, posInT, out, outOff, toCopy);
        generatedBytes += toCopy;
        toGenerate -= toCopy;
        outOff += toCopy;

        while (toGenerate > 0)
        {
            expandNext();
            toCopy = Math.min(hashLen, toGenerate);
            System.arraycopy(currentT, 0, out, outOff, toCopy);
            generatedBytes += toCopy;
            toGenerate -= toCopy;
            outOff += toCopy;
        }

        return len;
    }
}
