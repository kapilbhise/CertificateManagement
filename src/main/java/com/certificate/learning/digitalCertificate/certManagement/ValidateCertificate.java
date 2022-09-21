package com.certificate.learning.digitalCertificate.certManagement;

import java.io.*;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;


@SuppressWarnings("deprecation")
public class ValidateCertificate {

    //valid certificate=certificate signed by our ca local+not expired
    //Any of the two cases failed--->InvalidCertificate

    public boolean verifySignature(X509Certificate toVerify,X509Certificate signingCert) {
        Principal p = toVerify.getIssuerDN();
        String iss = p.getName();
        p = signingCert.getSubjectDN();
        String sub = p.getName();
        if (sub.equals(iss))
            return true;
        return false;
    }

    public String verifyExpiry(X509Certificate toVerify)
    {
        Date d=new Date(System.currentTimeMillis());
        long diff=(toVerify.getNotAfter().getTime()-d.getTime());
        if(diff>0)
        {
            return "notExpired";
        }
        return "expired";
    }

}

