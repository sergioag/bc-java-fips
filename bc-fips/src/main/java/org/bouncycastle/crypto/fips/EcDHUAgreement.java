package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.crypto.internal.params.EcDhuPublicParameters;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcNamedDomainParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;

class EcDHUAgreement<T extends FipsAgreementParameters>
    extends FipsAgreement<T>
{
    private final EcDhcuBasicAgreement dh;
    private final T parameter;

    EcDHUAgreement(EcDhcuBasicAgreement dh, T parameter)
    {
        this.dh = dh;
        this.parameter = parameter;
    }

    @Override
    public T getParameters()
    {
        return parameter;
    }

    @Override
    public byte[] calculate(AsymmetricPublicKey key)
    {
        AsymmetricECPublicKey ecKey = (AsymmetricECPublicKey)key;
        EcPublicKeyParameters lwECKey = new EcPublicKeyParameters(ecKey.getW(), getDomainParams(ecKey.getDomainParameters()));

        AsymmetricECPublicKey ephPublicKey = ((FipsEC.DHUAgreementParameters)parameter).getOtherPartyEphemeralKey();
        byte[] zBytes = dh.calculateAgreement(new EcDhuPublicParameters(lwECKey, new EcPublicKeyParameters(ephPublicKey.getW(), getDomainParams(ephPublicKey.getDomainParameters()))));

        return FipsKDF.processZBytes(zBytes, parameter);
    }

    private static EcDomainParameters getDomainParams(ECDomainParameters curveParams)
    {
        if (curveParams instanceof NamedECDomainParameters)
        {
            return new EcNamedDomainParameters((NamedECDomainParameters)curveParams);
        }
        return new EcDomainParameters(curveParams);
    }
}
