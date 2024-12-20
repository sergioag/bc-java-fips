/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.jcajce.interfaces;

import java.security.Key;

/**
 * Base interface for an EdDSA signing/verification key.
 */
public interface EdDSAKey
    extends Key
{
    byte[] getPublicData();
}
