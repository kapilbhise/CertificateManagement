package com.certificate.learning.digitalCertificate.certManagement;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Date;


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

