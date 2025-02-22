package com.certificate.learning.digitalCertificate.service;

import com.certificate.learning.digitalCertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalCertificate.bean.*;
import com.certificate.learning.digitalCertificate.certManagement.*;
import com.certificate.learning.digitalCertificate.exception.CertificatesNotFoundException;
import com.certificate.learning.digitalCertificate.repository.CertificatesRepository;
import com.certificate.learning.digitalCertificate.repository.LoginRepository;
import com.certificate.learning.digitalCertificate.util.EmailUtil;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@EnableScheduling
@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CertificatesRepository certificatesRepository;

    @Autowired
    private LoginRepository loginRepository;

    @Autowired
    private EmailUtil emailUtil;

    @Override
    public String generateSelfSignedCertificate(UserForm userForm) throws Exception {

        try {
            SelfSignedCertificateGenerator c = new SelfSignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L="
                    + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E="
                    + userForm.getEmail();
            X509Certificate cer = c.createCertificate(userForm.getAlias(), CERTIFICATE_DN);
            
            //try this
            System.out.println("Certificate generated is: "+ new String(Base64.encode(cer.getEncoded())));
//            return new String(Base64.encode(cer.getEncoded()));
            Certificates s = c.saveFile(cer, "src/main/java/com/certificate/learning/digitalCertificate/cer/"
                    + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            System.out.println(s.toString());
            System.out.println("Certificate will expire on" + cer.getNotAfter());
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Self Signed CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src/main/java/com/certificate/learning/digitalCertificate/cer/" + userForm.getAlias()
                            + ".cer");
            System.out.println("certificate created successfully and mailed");
            System.out.println("saved");

            return new String(Base64.encode(cer.getEncoded()));

        } catch (Exception e) {
            throw new CertificatesNotFoundException(
                    "Service:: There was a problem saving the certificate" + e.getMessage());
        }

    }

    @Override
    public String generateCaSignedCertificate(UserForm userForm) {
        try {
            CaSignedCertificateGenerator c = new CaSignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L="
                    + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E="
                    + userForm.getEmail();
            X509Certificate cert = c.createCertificate(userForm.getAlias(), CERTIFICATE_DN);
            System.out.println("saved");
            Certificates s = c.saveFile(cert, "src/main/java/com/certificate/learning/digitalCertificate/cer/"
                    + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            System.out.println(s.toString());
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Ca CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src/main/java/com/certificate/learning/digitalCertificate/cer/" + userForm.getAlias()
                            + ".cer");
            // return new String(Base64.encode(s.getCertificatetest().getEncoded()));
            System.out.println("certificate created successfully and mailed");
            return new String(Base64.encode(cert.getEncoded()));
        } catch (Exception e) {
            throw new CertificatesNotFoundException(
                    "Service: Issue while generating CA Signed cetificate: " + e.getMessage());
        }
    }

    @Override
    public String generateSignedCertificate(UserForm userForm) {
        // FileInputStream is = null;
        try {
            Certificates certificates = certificatesRepository.findById(1).get();
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(
                    java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));
            String dec = EncryptionDecryptionAES.decrypt(certificates.getCertificatetest(), pk);
            X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);

            SignedCertificateGenerator c = new SignedCertificateGenerator();
            System.out.println(certificate);
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L="
                    + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E="
                    + userForm.getEmail();
            X509Certificate certi = c.createSignedCertificate(certificate, pk, CERTIFICATE_DN, userForm.getAlias());
            Certificates s = c.saveFile(certi, "src/main/java/com/certificate/learning/digitalCertificate/cer/"
                    + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            System.out.println(s.toString());
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Signed CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src/main/java/com/certificate/learning/digitalCertificate/cer/" + userForm.getAlias()
                            + ".cer");
            // return new String(Base64.encode(s.getCertificatetest().getEncoded()));
            System.out.println("certificate created successfully and mailed");
            return new String(Base64.encode(certi.getEncoded()));
        } catch (Exception e) {
            throw new CertificatesNotFoundException(
                    "Service: Certificate Not Found: calocal.test is not found in db to generate a your signed certificate");
            // e.printStackTrace();
        }

    }
    // instead of @Scheduled(cron="0 0 12 * * ?") you can try
    // @Recurring(id = "my-recurring-job", cron = "0 0 12 * * ?")
    // @Job(name = "My recurring job")
    // Fire at 12:00 PM (noon) every day
    // for every minute-> * * * * * ?

    // this is working
    @Override
    @Scheduled(cron = "0 0 12 * * ?")
    public void notifyExpiry() throws Exception {
        List<Certificates> certificates = (List<Certificates>) certificatesRepository.findAll();
        for (int i = 0; i < certificates.size(); i++) {
            Certificates certificate = certificates.get(i);
            System.out.println("Mail reciever: " + certificate.getMail());
            KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact2.generatePrivate(new PKCS8EncodedKeySpec(
                    java.util.Base64.getDecoder().decode(certificate.getPrivatekey().getBytes("UTF-8"))));
            String decrypt = EncryptionDecryptionAES.decrypt(certificate.getCertificatetest(), pk);
            X509Certificate c = EncryptionDecryptionAES.convertToX509Cert(decrypt);
            Date d = new Date(System.currentTimeMillis());

            long diff = ((c.getNotAfter().getTime() - d.getTime()) / (1000 * 60 * 60 * 24)) % 365;

            System.out.println("difference between today and expiry date is: " + diff);
            if (diff < 0) {
                System.out.println("certificate: " + certificate.getAliasname() + " expired");
                // send mail without attachment
                emailUtil.sendEmail(certificate.getMail(), "ALERT!! CERTIFICATE EXPIRED",
                        "Dear User \nYour certificate " + certificate.getAliasname() + " is expired on "
                                + c.getNotAfter()
                                + ".\nPlease renew your certificate....\n\n\nTHANK YOU");
            } else if (diff <= 10) {
                // certificate is about to expire in diff days
                System.out.println(
                        "certificate: " + certificate.getAliasname() + " is about to expire in " + diff + " days");
                emailUtil.sendEmailWithAttachment(certificate.getMail(), "ALERT!!CERTIFICATE EXPIRY",
                        "Dear User \nYour certificate " + certificate.getAliasname() + " is about to expire in " + diff
                                + " days! \nPlease renew your certificate....\n\n\nTHANK YOU",
                        "src/main/java/com/certificate/learning/digitalCertificate/cer/"
                                + certificate.getAliasname() + ".cer");
            } else {
                System.out.println("No need to send the mail, there is a lot of time for expiration date");
            }
        }
    }

    @Override
    public String renewCertificate(RenewForm userForm) {
        String res = "";
        FileInputStream is = null;
        try {
            Certificates certificates = certificatesRepository.findById(1).get();
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(
                    java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));

            Certificates m = certificatesRepository.getcertest(userForm.getAlias());
            PrivateKey pkm = keyFact.generatePrivate(
                    new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String dec = EncryptionDecryptionAES.decrypt(m.getCertificatetest(), pkm);
            X509Certificate certi = EncryptionDecryptionAES.convertToX509Cert(dec);

            System.out.println(certi.getNotAfter());
            RenewCertificate renewedCertificate = new RenewCertificate();
            long l = ((certi.getNotAfter().getTime() - (new Date(System.currentTimeMillis()).getTime()))
                    / ((1000 * 60 * 60 * 24)));
            System.out.println("certificate will expire in: " + l + " days");
            if (l < 0) {
                return "certificate expired, request for new one";
            } else if (l > 0 && l < 10) {
                X509Certificate c = renewedCertificate.renewCertificate(certi, pk, userForm.getRenewYears(),
                        userForm.getAlias());
                
                Certificates s = renewedCertificate.saveFile(c,
                        "src/main/java/com/certificate/learning/digitalCertificate/cer/" + userForm.getAlias()
                                + ".cer");
                System.out.println(s.getCertificatetest());
                // s.setCertificatetest(s.getCertificatetest());
                // certificatesRepository.save(s);
                certificatesRepository.updateByAlias(userForm.getAlias(), s.getCertificatetest());
                // Certificate n =
                // certificatesRepository.getcertest(userForm.getAlias()).getCertificatetest();
                // System.out.println(n);
                emailUtil.sendEmailWithAttachment(m.getMail(),
                        "Renewed CERTIFICATE",
                        "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                        "src/main/java/com/certificate/learning/digitalCertificate/cer/" + userForm.getAlias()
                                + ".cer");
                System.out.println("certificate renewed successfully and mailed");
                return "Certificate renewed successfully";
            } else {
                return "There is still time for renewal";
            }

        } catch (Exception e) {
            throw new CertificatesNotFoundException(
                    "Service: Certificate Not Found: The certificate you are tyring to renew is not found in db");
            // e.printStackTrace();
        } finally {
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    throw new CertificatesNotFoundException(
                            "Service: Certificate Not Found: The certificate you are tyring to renew is not found in db");
                    // e.printStackTrace();
                }
            }
        }
        // return res;
    }

    @Override
    public String validateCertificate(String alias) throws Exception {
        String res = "";
        Certificates certificates = certificatesRepository.findById(1).get();
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(
                java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));
        String dec = EncryptionDecryptionAES.decrypt(certificates.getCertificatetest(), pk);
        X509Certificate authCertCer = EncryptionDecryptionAES.convertToX509Cert(dec);
        X509Certificate toVerifyCer;
        try {
            Certificates m = certificatesRepository.getcertest(alias);
            KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
            PrivateKey pkm = keyFact2.generatePrivate(
                    new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String decrypt = EncryptionDecryptionAES.decrypt(m.getCertificatetest(), pkm);
            toVerifyCer = EncryptionDecryptionAES.convertToX509Cert(decrypt);

        } catch (Exception e) {
            throw new CertificatesNotFoundException(
                    "Service: Certificate Not found : certificate you are trying to validate is not found in db");
            // return "notFound";
        }
        System.out.println(authCertCer);
        System.out.println(toVerifyCer);

        ValidateCertificate v = new ValidateCertificate();

        boolean val = v.verifySignature(toVerifyCer, authCertCer);
        String exp = v.verifyExpiry(toVerifyCer);

        if (val == true) {
            if (exp.equals("expired")) {
                res = "expired";
            } else if (exp.equals("notExpired")) {
                res = "valid";
            }
        } else if (val == false) {

            if (exp.equals("expired")) {
                res = "invalidExpired";
            } else if (exp.equals("notExpired")) {
                res = "selfSigned";
            }

        }
        return res;
    }

    @Override
    public String getCertificateByAlias(String alias) throws Exception {
        // TODO Auto-generated method stub
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        Certificates m = certificatesRepository.getcertest(alias);
        PrivateKey pkm = keyFact.generatePrivate(
                new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
        String dec = EncryptionDecryptionAES.decrypt(m.getCertificatetest(), pkm);
        X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);

        if (certificate == null) {
            throw new CertificatesNotFoundException(
                    "Service:: Certificate Not Found: The certifcate with " + alias + "  is not present in db");
        }
        String s;
        try {
            s = new String(Base64.encode(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            // TODO Auto-generated catch block
            return e.getMessage();
        }
        return s;
    }

    @Override
    public String loginUser(LoginForm loginform) throws LoginException {
        Login login1 = loginRepository.getUser(loginform.getName());
        if (login1 == null)
            throw new LoginException("no such user");
        else if (!(login1.getPassword().equals(loginform.getPwd())))
            throw new LoginException("wrong password");
        return "welcome";
    }

    @Override
    public void saveUser(LoginForm loginForm) throws LoginException {
        Login login1 = loginRepository.getUser(loginForm.getName());
        if (login1 != null)
            throw new LoginException("user exists");
        Login login = new Login();
        login.setUsername(loginForm.getName());
        login.setPassword(loginForm.getPwd());
        loginRepository.save(login);
    }

    @Override
    public String usercerts(String username) throws Exception {
        String res = "";
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        List<Certificates> list = certificatesRepository.getCertByUser(username);
        if (list.size() == 0)
            return "no certificates yet";
        for (Certificates m : list) {
            ArrayList<String> temp = new ArrayList<>();
            PrivateKey pkm = keyFact.generatePrivate(
                    new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String dec = EncryptionDecryptionAES.decrypt(m.getCertificatetest(), pkm);
            X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);
            res += m.getAliasname() + "," + certificate.getNotBefore().toGMTString() + ","
                    + certificate.getNotAfter().toGMTString() + "\n";
            /*
             * temp.add(m.getAliasname());
             * temp.add(certificate.getNotBefore().toString());
             * temp.add(certificate.getNotAfter().toString());
             * res.add(temp);
             */

        }
        return res.substring(0, res.length() - 1);

    }
}
