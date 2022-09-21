package com.certificate.learning.digitalCertificate.certManagement;

import com.certificate.learning.digitalCertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalCertificate.bean.Certificates;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;


@SuppressWarnings("deprecation")
public class RenewCertificate {
    public Certificates certificates1 = new Certificates();


    static {
        // adds the Bouncy castle provider to java security
        //BouncyCastle acts similar to keytool to generate certificate
        Security.addProvider(new BouncyCastleProvider());
    }


    public X509Certificate renewCertificate(X509Certificate certificate,PrivateKey privateKey,int renewyears, String alias) throws Exception{
        X509Certificate cert = certificate;
        //no need new keypair generation
        //all parameters are retained as same
        X509V3CertificateGenerator v3CertGen =  new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(certificate.getSerialNumber());
        v3CertGen.setIssuerDN(certificate.getIssuerX500Principal());
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        //expiry date set as asked
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*renewyears)));
        v3CertGen.setSubjectDN(certificate.getSubjectX500Principal());
        v3CertGen.setPublicKey(certificate.getPublicKey());
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        //for self signed cert
        //v3CertGen.addExtension(X509Extensions.BasicConstraints.getId(),true,new BasicConstraints(false));
        //for ca cert...place in trusted dir
        v3CertGen.addExtension(X509Extensions.BasicConstraints.getId(),true,new BasicConstraints(true));
        //sign the certificate again
        cert = v3CertGen.generateX509Certificate(privateKey);
        saveCert(cert,privateKey,alias);
        return cert;
    }


    public Certificates saveFile(X509Certificate cert,String Filename) throws Exception {
        final FileOutputStream os = new FileOutputStream(Filename);
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.write(Base64.encode(cert.getEncoded()));
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.close();
        return certificates1;
    }

    public void saveCert(X509Certificate cert, PrivateKey key,String CERTIFICATE_ALIAS) throws Exception {
        String s = new String(Base64.encode(cert.getEncoded()));
        String enc = EncryptionDecryptionAES.encrypt(s,cert.getPublicKey());
        certificates1.setCertificatetest(enc);

    }}

