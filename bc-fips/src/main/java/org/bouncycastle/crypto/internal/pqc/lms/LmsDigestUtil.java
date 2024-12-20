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

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        return digestProvider.getDigest(oid);
    }

    static String getDigestName(ASN1ObjectIdentifier oid)
    {
        String name = oidToName.get(oid);
        if (name != null)
        {
            return name;
        }

        throw new IllegalArgumentException("unrecognized digest oid: " + oid);
    }

    static ASN1ObjectIdentifier getDigestOID(String name)
    {
        ASN1ObjectIdentifier oid = nameToOid.get(name);
        if (oid != null)
        {
            return oid;
        }

        throw new IllegalArgumentException("unrecognized digest name: " + name);
    }

    public static int getDigestSize(Digest digest)
    {
        if (digest instanceof Xof)
        {
            return digest.getDigestSize() * 2;
        }

        return digest.getDigestSize();
    }
}
