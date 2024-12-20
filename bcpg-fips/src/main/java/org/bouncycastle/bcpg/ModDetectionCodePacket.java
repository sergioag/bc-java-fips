package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * basic packet for a modification detection code packet.
 */
public class ModDetectionCodePacket 
    extends ContainedPacket
{    
    private byte[]    digest;

    ModDetectionCodePacket(
            BCPGInputStream in)
            throws IOException
    {
        this(in, false);
    }

    ModDetectionCodePacket(
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        super(MOD_DETECTION_CODE, newPacketFormat);

        this.digest = new byte[20];
        in.readFully(this.digest);
    }
    
    public ModDetectionCodePacket(
        byte[]    digest)
        throws IOException
    {
        super(MOD_DETECTION_CODE);

        this.digest = new byte[digest.length];
        
        System.arraycopy(digest, 0, this.digest, 0, this.digest.length);
    }
    
    public byte[] getDigest()
    {
        byte[] tmp = new byte[digest.length];
        
        System.arraycopy(digest, 0, tmp, 0, tmp.length);
        
        return tmp;
    }
    
    public void encode(
        BCPGOutputStream    out) 
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), MOD_DETECTION_CODE, digest);
    }
}
