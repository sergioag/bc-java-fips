/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

import org.bouncycastle.crypto.internal.Digest;

import static org.bouncycastle.crypto.internal.pqc.lms.LM_OTS.D_MESG;
import static org.bouncycastle.crypto.internal.pqc.lms.LM_OTS.SEED_LEN;
import static org.bouncycastle.crypto.internal.pqc.lms.LM_OTS.SEED_RANDOMISER_INDEX;

class LMOtsPrivateKey
{
    private final LMOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] masterSecret;

    public LMOtsPrivateKey(LMOtsParameters parameter, byte[] i, int q, byte[] masterSecret)
    {
        this.parameter = parameter;
        I = i;
        this.q = q;
        this.masterSecret = masterSecret;
    }

    LMSContext getSignatureContext(LMSigParameters sigParams, byte[][] path)
    {
        byte[] C = new byte[SEED_LEN];

        SeedDerive derive = getDerivationFunction();
        derive.setJ(SEED_RANDOMISER_INDEX); // This value from reference impl.
        derive.deriveSeed(C, false);

        Digest ctx = LmsDigestUtil.getDigest(parameter.getDigestOID());

        LmsUtils.byteArray(this.getI(), ctx);
        LmsUtils.u32str(this.getQ(), ctx);
        LmsUtils.u16str(D_MESG, ctx);
        LmsUtils.byteArray(C, ctx);

        return new LMSContext(this, sigParams, ctx, C, path);
    }

    SeedDerive getDerivationFunction()
    {
        SeedDerive derive = new SeedDerive(I, masterSecret, LmsDigestUtil.getDigest(parameter.getDigestOID()));
        derive.setQ(q);
        return derive;
    }


    public LMOtsParameters getParameter()
    {
        return parameter;
    }

    public byte[] getI()
    {
        return I;
    }

    public int getQ()
    {
        return q;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }
}
