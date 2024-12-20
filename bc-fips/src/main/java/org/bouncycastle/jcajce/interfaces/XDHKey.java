/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.jcajce.interfaces;

import java.security.Key;

/**
 * Base interface for XDH agreement keys.
 */
public interface XDHKey
    extends Key
{
    byte[] getPublicData();
}
