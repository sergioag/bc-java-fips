/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;

public abstract class LMSKeyParameters
    extends AsymmetricKeyParameter
{
    protected LMSKeyParameters(boolean isPrivateKey)
    {
        super(isPrivateKey);
    }

    abstract public byte[] getEncoded();
}
