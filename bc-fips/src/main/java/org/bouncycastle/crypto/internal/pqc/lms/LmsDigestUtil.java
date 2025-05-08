package org.bouncycastle.crypto.internal.pqc.lms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Xof;

/**
 * LMS digest utils provides oid mapping to provider digest name.
 */
public class LmsDigestUtil
{
    private static Map<String, ASN1ObjectIdentifier> nameToOid = new HashMap<String, ASN1ObjectIdentifier>();
    private static Map<ASN1ObjectIdentifier, String> oidToName = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        nameToOid.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        nameToOid.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        nameToOid.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        nameToOid.put("SHAKE256", NISTObjectIdentifiers.id_shake256);

        oidToName.put(NISTObjectIdentifiers.id_sha256, "SHA-256");
        oidToName.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
        oidToName.put(NISTObjectIdentifiers.id_shake128, "SHAKE128");
        oidToName.put(NISTObjectIdentifiers.id_shake256, "SHAKE256");
    }

    static DigestProvider digestProvider;

    public static void setProvider(DigestProvider digProv)
    {
        digestProvider = digProv;
    }

    static Digest getDigest(LMOtsParameters otsParameters)
    {
        return createDigest(otsParameters.getDigestOID(), otsParameters.getN());
    }

    static Digest getDigest(LMSigParameters lmSigParameters)
    {
        return createDigest(lmSigParameters.getDigestOID(), lmSigParameters.getM());
    }

    private static Digest createDigest(ASN1ObjectIdentifier digOid, int digLen)
    {
        Digest dig = digestProvider.getDigest(digOid);
        if (digOid.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return new WrapperDigest(dig, digLen);
        }
        if (digLen == 24)
        {
            return new WrapperDigest(dig, digLen);
        }
        return dig;
    }

    static class WrapperDigest
        implements Digest
    {

        private final Digest dig;
        private final int length;

        WrapperDigest(Digest dig, int length)
        {
            this.dig = dig;
            this.length = length;
        }

        @Override
        public String getAlgorithmName()
        {
            return dig.getAlgorithmName() + "/" + length * 8;
        }

        @Override
        public int getDigestSize()
        {
            return length;
        }

        @Override
        public void update(byte in)
        {
             dig.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            dig.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            byte[] digOut = new byte[dig.getDigestSize()];

            dig.doFinal(digOut, 0);

            System.arraycopy(digOut, 0, out, outOff, length);
            return length;
        }

        @Override
        public void reset()
        {
            dig.reset();
        }

        @Override
        public int getByteLength()
        {
            return dig.getByteLength();
        }
    }
}
