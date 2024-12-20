package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Basic type for a trust packet
 */
public class TrustPacket 
    extends ContainedPacket
{    
    byte[]    levelAndTrustAmount;

    public TrustPacket(
            BCPGInputStream  in)
            throws IOException
    {
        this(in, false);
    }

    public TrustPacket(
        BCPGInputStream  in,
        boolean newPacketFormat)
        throws IOException
    {
        super(TRUST, newPacketFormat);

        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        int                      ch;
        
        while ((ch = in.read()) >= 0)
        {
            bOut.write(ch);
        }
        
        levelAndTrustAmount = bOut.toByteArray();
    }
    
    public TrustPacket(
        int    trustCode)
    {
        super(TRUST);

        this.levelAndTrustAmount = new byte[1];
        
        this.levelAndTrustAmount[0] = (byte)trustCode;
    }

    public byte[] getLevelAndTrustAmount()
    {
        return levelAndTrustAmount;
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), TRUST, levelAndTrustAmount);
    }
}
