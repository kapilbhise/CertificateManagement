package com.certificate.learning.digitalCertificate.certManagement;

import java.security.*;
import java.io.FileOutputStream;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;

import com.certificate.learning.digitalCertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalCertificate.bean.Certificates;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.security.auth.x500.X500Principal;

public class unsignedCertificate {
    static {

        // adds the Bouncy castle provider to java security
        //BouncyCastle acts similar to keytool to generate certificate
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int CERTIFICATE_BITS = 1024;
    public Certificates certificates1 = new Certificates();
    //X500Principal subject = new X500Principal("C=NO, ST=Trondheim, L=Trondheim, O=Senthadev, OU=Innovation, CN=www.senthadev.com, EMAILADDRESS=senthadev@gmail.com");

    /*public static void main(String[] args) throws Exception {
        unsignedCertificate uc = new unsignedCertificate();

        PKCS10CertificationRequest cert=uc.create();
    }*/



    public Certificates create(String CERTIFICATE_ALIAS,String subject) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(CERTIFICATE_BITS, new SecureRandom());
        KeyPair pair = gen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
        X500Principal subj = new X500Principal(subject);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subj, publicKey);
        PKCS10CertificationRequest csr = builder.build(signGen);
        System.out.println(builder);

        final FileOutputStream os = new FileOutputStream("src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + CERTIFICATE_ALIAS + ".cer");
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.write(Base64.encode(csr.getEncoded()));
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.close();

        certificates1.setCertificatetest(new String(Base64.encode(csr.getEncoded())));
        certificates1.setCaflag("F");
        certificates1.setAliasname(CERTIFICATE_ALIAS);
        certificates1.setPrivatekey(new String(Base64.encode(privateKey.getEncoded())));
        certificates1.setPublickey(new String(Base64.encode(publicKey.getEncoded())));
        System.out.println(csr);
        return certificates1;
    }


    public unsignedCertificate() throws Exception {
    }
}
