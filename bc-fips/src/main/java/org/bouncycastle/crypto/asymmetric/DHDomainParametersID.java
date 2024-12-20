package org.bouncycastle.crypto.asymmetric;

/**
 * Base interface for an DH domain parameters ID.
 */
public interface DHDomainParametersID
{
    /**
     * Return the string version of the parameters name.
     *
     * @return the name of the parameters.
     */
    String getName();
}
