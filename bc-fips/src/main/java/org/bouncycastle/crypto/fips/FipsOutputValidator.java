package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.OutputValidator;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for a FIPS signature verifier.
 *
 * @param <T> The parameters class for this verifier.
 */
public abstract class FipsOutputValidator<T extends Parameters>
    implements OutputValidator<T>
{
    // package protect construction
    FipsOutputValidator()
    {
    }

    public abstract T getParameters();

    public abstract org.bouncycastle.crypto.UpdateOutputStream getValidatingStream();

    public abstract boolean isValidated();
}
