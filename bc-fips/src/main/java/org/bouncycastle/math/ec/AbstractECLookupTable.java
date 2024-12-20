/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.math.ec;

public abstract class AbstractECLookupTable
    implements ECLookupTable
{
    public ECPoint lookupVar(int index)
    {
        return lookup(index);
    }
}
