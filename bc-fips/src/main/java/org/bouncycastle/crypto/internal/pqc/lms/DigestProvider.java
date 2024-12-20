package org.bouncycastle.crypto.internal.pqc.lms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.internal.Digest;

public interface DigestProvider
{
    Digest getDigest(ASN1ObjectIdentifier digOid);
}
