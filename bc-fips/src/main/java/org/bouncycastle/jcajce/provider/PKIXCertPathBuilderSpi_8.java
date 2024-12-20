package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;

/**
 * Implements the PKIX CertPathBuilding algorithm for BouncyCastle.
 * 
 * @see CertPathBuilderSpi
 */
class PKIXCertPathBuilderSpi_8
    extends CertPathBuilderSpi
{
    private final JcaJceKeyHelper helper;
    private final boolean isForCRLCheck;

    public PKIXCertPathBuilderSpi_8(BouncyCastleFipsProvider fipsProvider)
    {
        this(fipsProvider, false);
    }

    PKIXCertPathBuilderSpi_8(BouncyCastleFipsProvider fipsProvider, boolean isForCRLCheck)
    {
        this(new JcaJceKeyHelper(fipsProvider), isForCRLCheck);
    }

    PKIXCertPathBuilderSpi_8(JcaJceKeyHelper helper, boolean isForCRLCheck)
    {
        this.helper = helper;
        this.isForCRLCheck = isForCRLCheck;
    }

    public PKIXCertPathChecker engineGetRevocationChecker()
    {
        return new ProvRevocationChecker(helper);
    }

    /**
     * Build and validate a CertPath using the given parameter.
     * 
     * @param params PKIXBuilderParameters object containing all information to
     *            build the CertPath
     */
    public CertPathBuilderResult engineBuild(CertPathParameters params)
        throws CertPathBuilderException, InvalidAlgorithmParameterException
    {
        PKIXExtendedBuilderParameters pkixParams = null;
        if (params instanceof PKIXExtendedBuilderParameters)
        {
            pkixParams = (PKIXExtendedBuilderParameters) params;
        }
        else if (params instanceof PKIXBuilderParameters)
        {
            pkixParams = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)params).build();
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                "Parameters must be an instance of "
                    + PKIXBuilderParameters.class.getName() + " or "
                    + PKIXExtendedBuilderParameters.class.getName() + ".");
        }


        Iterator targetIter;
        List certPathList = new ArrayList();
        X509Certificate cert;

        // search target certificates
        Collection targets = CertPathValidatorUtilities.findTargets(pkixParams);

        CertPathBuilderResult result = null;

        // check all potential target certificates
        targetIter = targets.iterator();
        while (targetIter.hasNext() && result == null)
        {
            cert = (X509Certificate) targetIter.next();
            result = build(cert, pkixParams, certPathList);
        }

        if (result == null && certPathException != null)
        {
            if (certPathException instanceof AnnotatedException)
            {
                throw new CertPathBuilderException(certPathException.getMessage(), certPathException.getCause());
            }
            throw new CertPathBuilderException(
                "Possible certificate chain could not be validated.",
                certPathException);
        }

        if (result == null && certPathException == null)
        {
            throw new CertPathBuilderException(
                "Unable to find certificate chain.");
        }

        return result;
    }

    private Exception certPathException;

    protected CertPathBuilderResult build(X509Certificate tbvCert,
        PKIXExtendedBuilderParameters pkixParams, List tbvPath)
    {
        // If tbvCert is readily present in tbvPath, it indicates having run
        // into a cycle in the
        // PKI graph.
        if (tbvPath.contains(tbvCert))
        {
            return null;
        }
        // step out, the certificate is not allowed to appear in a certification
        // chain.
        if (pkixParams.getExcludedCerts().contains(tbvCert))
        {
            return null;
        }
        // test if certificate path exceeds maximum length
        if (pkixParams.getMaxPathLength() != -1)
        {
            if (tbvPath.size() - 1 > pkixParams.getMaxPathLength())
            {
                return null;
            }
        }

        tbvPath.add(tbvCert);

        CertPathBuilderResult builderResult = null;

        try
        {
            CertificateFactory cFact;
            PKIXCertPathValidatorSpi_8 validator;

            try
            {
                cFact = new CertificateFactory(helper);
                validator = new PKIXCertPathValidatorSpi_8(helper, isForCRLCheck);
            }
            catch (Exception e)
            {
                // cannot happen
                throw new RuntimeException("Exception creating support classes.");
            }

            // check whether the issuer of <tbvCert> is a TrustAnchor
            if (CertPathValidatorUtilities.isIssuerTrustAnchor(tbvCert, pkixParams.getBaseParameters().getTrustAnchors(),
                pkixParams.getBaseParameters().getSigProvider()))
            {
                // exception message from possibly later tried certification
                // chains
                CertPath certPath = null;
                PKIXCertPathValidatorResult result = null;
                try
                {
                    certPath = cFact.engineGenerateCertPath(tbvPath);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                        "Certification path could not be constructed from certificate list.",
                        e);
                }

                try
                {
                    result = (PKIXCertPathValidatorResult) validator.engineValidate(
                        certPath, pkixParams);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                        "Certification path could not be validated.", e);
                }

                return new PKIXCertPathBuilderResult(certPath, result
                    .getTrustAnchor(), result.getPolicyTree(), result
                    .getPublicKey());

            }
            else
            {
                List stores = new ArrayList();


                stores.addAll(pkixParams.getBaseParameters().getCertificateStores());

                // add additional X.509 stores from locations in certificate
                try
                {
                    stores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(
                        tbvCert.getExtensionValue(Extension.issuerAlternativeName.getId()), pkixParams.getBaseParameters().getNamedCertificateStoreMap()));
                }
                catch (CertificateParsingException e)
                {
                    throw new AnnotatedException(
                        "No additional X.509 stores can be added from certificate locations.",
                        e);
                }
                Collection issuers = new HashSet();
                // try to get the issuer certificate from one
                // of the stores
                try
                {
                    issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(tbvCert, pkixParams.getBaseParameters().getCertStores(), stores));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                        "Cannot find issuer certificate for certificate in certification path.",
                        e);
                }
                if (issuers.isEmpty())
                {
                    throw new AnnotatedException(
                        "No issuer certificate for certificate in certification path found.");
                }
                Iterator it = issuers.iterator();

                while (it.hasNext() && builderResult == null)
                {
                    X509Certificate issuer = (X509Certificate) it.next();
                    builderResult = build(issuer, pkixParams, tbvPath);
                }
            }
        }
        catch (AnnotatedException e)
        {
            certPathException = e;
        }
        if (builderResult == null)
        {
            tbvPath.remove(tbvCert);
        }
        return builderResult;
    }

}
