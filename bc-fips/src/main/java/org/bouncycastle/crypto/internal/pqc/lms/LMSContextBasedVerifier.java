/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

import java.io.IOException;

public interface LMSContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature)
        throws IOException;

    boolean verify(LMSContext context);
}
