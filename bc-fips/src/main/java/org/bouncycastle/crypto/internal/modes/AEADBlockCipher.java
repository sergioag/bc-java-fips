/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.modes;

import org.bouncycastle.crypto.internal.BlockCipher;

/**
 * A block cipher mode that includes authenticated encryption with a streaming mode and optional associated data.
 * <p/>
 * Implementations of this interface may operate in a packet mode (where all input data is buffered and 
 * processed dugin the call to {@link #doFinal(byte[], int)}), or in a streaming mode (where output data is
 * incrementally produced with each call to {@link #processByte(byte, byte[], int)} or 
 * {@link #processBytes(byte[], int, int, byte[], int)}.
 * <br/>This is important to consider during decryption: in a streaming mode, unauthenticated plaintext data
 * may be output prior to the call to {@link #doFinal(byte[], int)} that results in an authentication
 * failure. The higher level protocol utilising this cipher must ensure the plaintext data is handled 
 * appropriately until the end of data is reached and the entire ciphertext is authenticated.
 * @see org.bouncycastle.crypto.internal.params.AEADParameters
 */
public interface AEADBlockCipher
    extends AEADCipher
{
    /**
     * return the cipher this object wraps.
     *
     * @return the cipher this object wraps.
     */
    BlockCipher getUnderlyingCipher();
}
