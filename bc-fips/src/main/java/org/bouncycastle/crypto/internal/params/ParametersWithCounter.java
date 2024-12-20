/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.CipherParameters;

public class ParametersWithCounter
    implements CipherParameters
{
    private final int counter;
    private final CipherParameters    parameters;

    public ParametersWithCounter(
        CipherParameters    parameters,
        int counter)
    {
        this.parameters = parameters;
        this.counter = counter;
    }

    public int getCounter()
    {
        return counter;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
