package org.bouncycastle.crypto;

public interface AlphabetMapper
{
    int getRadix();

    byte[] convertToIndexes(char[] input);

    char[] convertToChars(byte[] input);
}
