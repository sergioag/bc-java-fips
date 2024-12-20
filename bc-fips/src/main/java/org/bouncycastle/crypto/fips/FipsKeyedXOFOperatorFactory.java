package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.KeyedXOFOperatorFactory;
import org.bouncycastle.crypto.SymmetricKey;

/**
 * Base class for the approved mode KeyedXOFOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsKeyedXOFOperatorFactory<T extends FipsParameters>
    implements KeyedXOFOperatorFactory<T>
{
    // package protect constructor
    FipsKeyedXOFOperatorFactory()
    {
        FipsStatus.isReady();
    }

    public abstract FipsOutputXOFCalculator<T> createOutputXOFCalculator(SymmetricKey key, T parameter);
}
