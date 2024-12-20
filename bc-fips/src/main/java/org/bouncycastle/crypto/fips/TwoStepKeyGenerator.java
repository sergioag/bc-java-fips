package org.bouncycastle.crypto.fips;


import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.macs.CMac;
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
class TwoStepKeyGenerator
{
    private Mac mac;
    private int macLen;

    public TwoStepKeyGenerator(Mac mac)
    {
        this.mac = mac;
        if (mac instanceof HMac)
        {
            this.macLen = ((HMac)mac).getUnderlyingDigest().getDigestSize();
        }
        else
        {
            this.macLen = ((CMac)mac).getMacSize();
        }
    }

    public KeyParameter generate(HKDFKeyParameters params)
    {
        return extract(params.getSalt(), params.getIKM());
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
            mac.init(new KeyParameterImpl(new byte[macLen]));
        }
        else
        {
            mac.init(new KeyParameterImpl(salt));
        }

        mac.update(ikm, 0, ikm.length);

        byte[] prk = new byte[macLen];
        mac.doFinal(prk, 0);

        return new KeyParameterImpl(prk);
    }
}
