package org.bouncycastle.jcajce.spec;

import org.bouncycastle.crypto.fips.FipsLMS;
import org.bouncycastle.crypto.general.LMS;

public class LMOtsParameters
{
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(FipsLMS.sha256_n32_w1);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(FipsLMS.sha256_n32_w2);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(FipsLMS.sha256_n32_w4);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(FipsLMS.sha256_n32_w8);
    public static final LMOtsParameters sha256_n24_w1 = new LMOtsParameters(FipsLMS.sha256_n24_w1);
    public static final LMOtsParameters sha256_n24_w2 = new LMOtsParameters(FipsLMS.sha256_n24_w2);
    public static final LMOtsParameters sha256_n24_w4 = new LMOtsParameters(FipsLMS.sha256_n24_w4);
    public static final LMOtsParameters sha256_n24_w8 = new LMOtsParameters(FipsLMS.sha256_n24_w8);

    public static final LMOtsParameters shake256_n32_w1 = new LMOtsParameters(FipsLMS.shake256_n32_w1);
    public static final LMOtsParameters shake256_n32_w2 = new LMOtsParameters(FipsLMS.shake256_n32_w2);
    public static final LMOtsParameters shake256_n32_w4 = new LMOtsParameters(FipsLMS.shake256_n32_w4);
    public static final LMOtsParameters shake256_n32_w8 = new LMOtsParameters(FipsLMS.shake256_n32_w8);
    public static final LMOtsParameters shake256_n24_w1 = new LMOtsParameters(FipsLMS.shake256_n24_w1);
    public static final LMOtsParameters shake256_n24_w2 = new LMOtsParameters(FipsLMS.shake256_n24_w2);
    public static final LMOtsParameters shake256_n24_w4 = new LMOtsParameters(FipsLMS.shake256_n24_w4);
    public static final LMOtsParameters shake256_n24_w8 = new LMOtsParameters(FipsLMS.shake256_n24_w8);
    
    final FipsLMS.OTSParameters otsParameters;

    LMOtsParameters(FipsLMS.OTSParameters otsParameters)
    {
        this.otsParameters = otsParameters;
    }
}
