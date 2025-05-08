package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;

/**
 * Generator for Version 3 TBSCertificateStructures.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] Extensions OPTIONAL
 *      }
 * </pre>
 *
 */
class V3TBSCertificateGenerator
{
    private static final DERTaggedObject VERSION = new DERTaggedObject(true, 0, new ASN1Integer(2));

    ASN1Integer             serialNumber;
    AlgorithmIdentifier signature;
    X500Name                issuer;
    Validity                validity;
    Time startDate, endDate;
    X500Name                subject;
    SubjectPublicKeyInfo subjectPublicKeyInfo;
    Extensions extensions;

    private boolean altNamePresentAndCritical;
    private DERBitString issuerUniqueID;
    private DERBitString subjectUniqueID;

    public V3TBSCertificateGenerator()
    {
    }

    public void setSerialNumber(
        ASN1Integer  serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public void setSignature(
        AlgorithmIdentifier    signature)
    {
        this.signature = signature;
    }

    public void setIssuer(
        X500Name issuer)
    {
        this.issuer = issuer;
    }

    public void setValidity(Validity validity)
    {
        this.validity = validity;
        this.startDate = null;
        this.endDate = null;
    }

    public void setStartDate(Time startDate)
    {
        this.validity = null;
        this.startDate = startDate;
    }

    public void setStartDate(ASN1UTCTime startDate)
    {
        setStartDate(new Time(startDate));
    }

    public void setEndDate(Time endDate)
    {
        this.validity = null;
        this.endDate = endDate;
    }

    public void setEndDate(ASN1UTCTime endDate)
    {
        setEndDate(new Time(endDate));
    }

    public void setSubject(
        X500Name subject)
    {
        this.subject = subject;
    }

    public void setIssuerUniqueID(
        DERBitString uniqueID)
    {
        this.issuerUniqueID = uniqueID;
    }

    public void setSubjectUniqueID(
        DERBitString uniqueID)
    {
        this.subjectUniqueID = uniqueID;
    }

    public void setSubjectPublicKeyInfo(
        SubjectPublicKeyInfo    pubKeyInfo)
    {
        this.subjectPublicKeyInfo = pubKeyInfo;
    }

    public void setExtensions(
        Extensions    extensions)
    {
        this.extensions = extensions;
        if (extensions != null)
        {
            Extension altName = extensions.getExtension(Extension.subjectAlternativeName);

            if (altName != null && altName.isCritical())
            {
                altNamePresentAndCritical = true;
            }
        }
    }

    public ASN1Sequence generatePreTBSCertificate()
    {
        if (signature != null)
        {
            throw new IllegalStateException("signature field should not be set in PreTBSCertificate");
        }
        if ((serialNumber == null) || (issuer == null) ||
            (validity == null && (startDate == null || endDate == null)) ||
            (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
        {
            throw new IllegalStateException("not all mandatory fields set in V3 TBScertificate generator");
        }

        ASN1EncodableVector v = new ASN1EncodableVector(9);

        v.add(VERSION);
        v.add(serialNumber);
        // No signature
        v.add(issuer);
        v.add(validity != null ? validity : new Validity(startDate, endDate));
        v.add(subject != null ? subject : X500Name.getInstance(new DERSequence()));
        v.add(subjectPublicKeyInfo);

        if (issuerUniqueID != null)
        {
            v.add(new DERTaggedObject(false, 1, issuerUniqueID));
        }

        if (subjectUniqueID != null)
        {
            v.add(new DERTaggedObject(false, 2, subjectUniqueID));
        }

        if (extensions != null)
        {
            v.add(new DERTaggedObject(true, 3, extensions));
        }

        return new DERSequence(v);
    }

    public TBSCertificate generateTBSCertificate()
    {
        if ((serialNumber == null) || (signature == null) || (issuer == null) ||
            (validity == null && (startDate == null || endDate == null)) ||
            (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
        {
            throw new IllegalStateException("not all mandatory fields set in V3 TBScertificate generator");
        }

        return TBSCertificate.getInstance(new TBSCert(new ASN1Integer(2), serialNumber, signature, issuer,
            validity != null ? validity : new Validity(startDate, endDate),
            subject != null ? subject : X500Name.getInstance(new DERSequence()), subjectPublicKeyInfo,
            issuerUniqueID, subjectUniqueID, extensions).toASN1Primitive());
    }
}
