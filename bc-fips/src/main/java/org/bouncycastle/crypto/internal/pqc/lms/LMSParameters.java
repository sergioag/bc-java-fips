/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

public class LMSParameters
{
    private final LMSigParameters lmSigParam;
    private final LMOtsParameters lmOTSParam;

    public LMSParameters(LMSigParameters lmSigParam, LMOtsParameters lmOTSParam)
    {
        this.lmSigParam = lmSigParam;
        this.lmOTSParam = lmOTSParam;
    }

    public LMSigParameters getLMSigParam()
    {
        return lmSigParam;
    }

    public LMOtsParameters getLMOTSParam()
    {
        return lmOTSParam;
    }
}
