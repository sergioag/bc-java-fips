package org.bouncycastle.asn1.smime;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * Handler for creating a vector S/MIME Capabilities
 */
public class SMIMECapabilityVector
{
    private ASN1EncodableVector    capabilities = new ASN1EncodableVector();

    public void addCapability(
        ASN1ObjectIdentifier capability)
    {
        capabilities.add(new DERSequence(capability));
    }

    public void addCapability(
        ASN1ObjectIdentifier capability,
        int                 value)
    {
        capabilities.add(new DERSequence(new ASN1Encodable[]{capability, new ASN1Integer(value)}));
    }

    public void addCapability(
        ASN1ObjectIdentifier capability,
        ASN1Encodable params)
    {
        capabilities.add(new DERSequence(new ASN1Encodable[]{capability, params}));
    }

    public ASN1EncodableVector toASN1EncodableVector()
    {
        return capabilities;
    }
}
