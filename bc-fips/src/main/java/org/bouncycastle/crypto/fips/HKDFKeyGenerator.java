package org.bouncycastle.crypto.fips;


import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.params.HKDFKeyParameters;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;

/**
 * Key Generator for HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
 * according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
 * Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
 * (output keying material) and is likely to have better security properties
 * than KDF's based on just a hash function.
 */
class HKDFKeyGenerator
{
    private HMac hMacHash;
    private int hashLen;

    /**
     * Creates a HKDFBytesGenerator based on the given hash function.
     *
     * @param hash the digest to be used as the source of generatedBytes bytes
     */
    public HKDFKeyGenerator(Digest hash)
    {
        this.hMacHash = new HMac(hash);
        this.hashLen = hash.getDigestSize();
    }

    public HKDFKeyGenerator(HMac hMac)
    {
        this.hMacHash = hMac;
        this.hashLen = hMac.getUnderlyingDigest().getDigestSize();
    }

    public KeyParameter generate(HKDFKeyParameters params)
    {
        if (params.skipExtract())
        {
            // use IKM directly as PRK
            return new KeyParameterImpl(params.getIKM());
        }
        else
        {
            return extract(params.getSalt(), params.getIKM());
        }
    }

    /**
     * Performs the extract part of the key derivation function.
     *
     * @param salt the salt to use
     * @param ikm  the input keying material
     * @return the PRK as KeyParameter
     */
    private KeyParameter extract(byte[] salt, byte[] ikm)
    {
        if (salt == null)
        {
            // TODO check if hashLen is indeed same as HMAC size
            hMacHash.init(new KeyParameterImpl(new byte[hashLen]));
        }
        else
        {
            hMacHash.init(new KeyParameterImpl(salt));
        }

        hMacHash.update(ikm, 0, ikm.length);

        byte[] prk = new byte[hashLen];
        hMacHash.doFinal(prk, 0);

        return new KeyParameterImpl(prk);
    }
}
