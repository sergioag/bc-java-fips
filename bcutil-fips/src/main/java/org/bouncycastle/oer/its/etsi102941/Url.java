package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;

public class Url
    extends ASN1Object
{
    private final String url;

    public Url(String url)
    {
        this.url = url;
    }

    private Url(DERIA5String url)
    {
        this.url = url.getString();
    }

    public static Url getInstance(Object o)
    {
        if (o instanceof Url)
        {
            return (Url)o;
        }

        if (o != null)
        {
            return new Url(DERIA5String.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERIA5String(url);
    }

    public String getUrl()
    {
        return url;
    }
}
