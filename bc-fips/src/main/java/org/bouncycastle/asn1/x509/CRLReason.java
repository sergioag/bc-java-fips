/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.Integers;

/**
 * The CRLReason enumeration.
 * <pre>
 * CRLReason ::= ENUMERATED {
 *  unspecified             (0),
 *  keyCompromise           (1),
 *  cACompromise            (2),
 *  affiliationChanged      (3),
 *  superseded              (4),
 *  cessationOfOperation    (5),
 *  certificateHold         (6),
 *  removeFromCRL           (8),
 *  privilegeWithdrawn      (9),
 *  aACompromise           (10)
 * }
 * </pre>
 */
public class CRLReason
    extends ASN1Object
{
    public static final int unspecified = 0;
    public static final int keyCompromise = 1;
    public static final int cACompromise = 2;
    public static final int affiliationChanged = 3;
    public static final int superseded = 4;
    public static final int cessationOfOperation  = 5;
    public static final int certificateHold = 6;
    // 7 -> unknown
    public static final int removeFromCRL = 8;
    public static final int privilegeWithdrawn = 9;
    public static final int aACompromise = 10;

    private static final String[] reasonString =
    {
        "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
        "superseded", "cessationOfOperation", "certificateHold", "unknown",
        "removeFromCRL", "privilegeWithdrawn", "aACompromise"
    };

    private static final Hashtable table = new Hashtable();

    private ASN1Enumerated value;

    public static CRLReason getInstance(Object o)
    {
        if (o instanceof CRLReason)
        {
            return (CRLReason)o;
        }
        else if (o != null)
        {
            return lookup(ASN1Enumerated.getInstance(o).intValueExact());
        }

        return null;
    }

    private CRLReason(
        int reason)
    {
        value = new ASN1Enumerated(reason);
    }

    public String toString()
    {
        String str;
        int reason = getValue().intValue();
        if (reason < 0 || reason > 10)
        {
            str = "invalid";
        }
        else
        {
            str = reasonString[reason];
        }
        return "CRLReason: " + str;
    }

    public BigInteger getValue()
    {
        return value.getValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }

    public static CRLReason lookup(int value)
    {
        Integer idx = Integers.valueOf(value);

        if (!table.containsKey(idx))
        {
            table.put(idx, new CRLReason(value));
        }

        return (CRLReason)table.get(idx);
    }
}
