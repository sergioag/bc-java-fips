package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class EcNamedDomainParameters
    extends EcDomainParameters
{
    private final ASN1ObjectIdentifier name;

    public EcNamedDomainParameters(NamedECDomainParameters namedParams)
    {
        super(namedParams);

        this.name = namedParams.getID();
    }

    public EcNamedDomainParameters(NamedECDomainParameters namedParams, BigInteger hInv)
    {
        super(namedParams, hInv);

        this.name = namedParams.getID();
    }

    public ASN1ObjectIdentifier getName()
    {
        return name;
    }

    // for the purposes of equality and hashCode we ignore the prescence of the name.
    public boolean equals(Object o)
    {
        return super.equals(o);
    }

    public int hashCode()
    {
        return super.hashCode();
    }
}
