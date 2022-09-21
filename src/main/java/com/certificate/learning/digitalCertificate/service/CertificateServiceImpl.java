package com.certificate.learning.digitalCertificate.service;

import com.certificate.learning.digitalCertificate.EncryptionDecryptionAES;
import com.certificate.learning.digitalCertificate.bean.Certificates;
import com.certificate.learning.digitalCertificate.bean.RenewForm;
import com.certificate.learning.digitalCertificate.bean.UserForm;
import com.certificate.learning.digitalCertificate.certManagement.*;
import com.certificate.learning.digitalCertificate.exception.CertificatesNotFoundException;
import com.certificate.learning.digitalCertificate.repository.CertificatesRepository;
import com.certificate.learning.digitalCertificate.util.EmailUtil;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@EnableScheduling
@Service
public class CertificateServiceImpl implements CertificateService{

    @Autowired
    private CertificatesRepository certificatesRepository;

    @Autowired
    private EmailUtil emailUtil;

    @Override
    public String generateSelfSignedCertificate(UserForm userForm) throws Exception {
        try {
            SelfSignedCertificateGenerator c = new SelfSignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L=" + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E=" + userForm.getEmail();
            X509Certificate cer = c.createCertificate(userForm.getAlias(), CERTIFICATE_DN);
            Certificates s = c.saveFile(cer, "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Self Signed CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
            return new String(Base64.encode(cer.getEncoded()));
        }
        catch(Exception e) {
            throw new CertificatesNotFoundException("");
        }

    }


    @Override
    public String generateCaSignedCertificate(UserForm userForm)  {
        try {
            CaSignedCertificateGenerator c = new CaSignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L=" + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E=" + userForm.getEmail();
            X509Certificate cert = c.createCertificate(userForm.getAlias(), CERTIFICATE_DN);
            Certificates s = c.saveFile(cert, "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Ca CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
            return new String(Base64.encode(cert.getEncoded()));
        }
        catch(Exception e) {
            throw new CertificatesNotFoundException("Service: Issue while generating CA Signed cetificate: "+e.getMessage());
        }
    }


    @Override
    public String generateUnsignedCertificate(UserForm userForm) throws Exception {
        try {
            unsignedCertificate c = new unsignedCertificate();
            String CERTIFICATE_DN = "C= " + userForm.getCountry() + ", ST=" + userForm.getState() +", L=" + userForm.getLocality() +", O=" + userForm.getOrganization() +  ", OU=Telstra India, CN=" + userForm.getCn()+  ", EMAILADDRESS=" + userForm.getEmail();
            Certificates cert = c.create(userForm.getAlias(), CERTIFICATE_DN);
            cert.setMail(userForm.getEmail());
            cert.setUsername(userForm.getName());
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Unsigned CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");

            return cert.getCertificatetest();
        }
        catch(Exception e) {
            throw new CertificatesNotFoundException("Service: Issue while generating CA Signed cetificate: "+e.getMessage());
        }
    }

    @Override
    public String generateSignedCertificate(UserForm userForm) {
        try {
            Certificates certificates = certificatesRepository.findById(1).get();
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));
            String dec= EncryptionDecryptionAES.decrypt(certificates.getCertificatetest(),pk);
            X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);


            SignedCertificateGenerator c = new SignedCertificateGenerator();
            String CERTIFICATE_DN = "CN=" + userForm.getCn() + ", O=" + userForm.getOrganization() + ", L=" + userForm.getLocality() + ", ST=" + userForm.getState() + ", C= " + userForm.getCountry() + ", E=" + userForm.getEmail();
            X509Certificate certi = c.createSignedCertificate(certificate, pk, CERTIFICATE_DN, userForm.getAlias());
            Certificates s = c.saveFile(certi, "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
            s.setMail(userForm.getEmail());
            s.setUsername(userForm.getName());
            certificatesRepository.save(s);
            emailUtil.sendEmailWithAttachment(userForm.getEmail(),
                    "Signed CERTIFICATE",
                    "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                    "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
            return new String(Base64.encode(certi.getEncoded()));
        } catch (Exception e) {
            throw new CertificatesNotFoundException("Service: Certificate Not Found: calocal.test is not found in db to generate a your signed certificate");
        }

    }


// instead of @Scheduled(cron="0 0 12 * * ?")  you can try
//    @Recurring(id = "my-recurring-job", cron = "0 0 12 * * ?")
//    @Job(name = "My recurring job")
//	Fire at 12:00 PM (noon) every day
// for every minute-> * * * * * ?

   //this is working
    @Override
    @Scheduled(cron = "0 0 12 * * ?")
    public void notifyExpiry() throws Exception {
        List<Certificates> certificates = (List<Certificates>) certificatesRepository.findAll();
        for (int i = 0; i < certificates.size(); i++) {
            Certificates certificate = certificates.get(i);
            KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
            PrivateKey pk = keyFact2.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificate.getPrivatekey().getBytes("UTF-8"))));
            String decrypt= EncryptionDecryptionAES.decrypt(certificate.getCertificatetest(),pk);
            X509Certificate c = EncryptionDecryptionAES.convertToX509Cert(decrypt);
            Date d = new Date(System.currentTimeMillis());

            long diff = ((c.getNotAfter().getTime() - d.getTime()) / (1000 * 60 * 60 * 24)) % 365;

            System.out.println("difference between today and expiry date is: " + diff);
            if (diff < 0) {
                System.out.println("certificate: " + certificate.getAliasname() + " expired");
                // send mail without attachment
                emailUtil.sendEmail(certificate.getMail(), "ALERT!! CERTIFICATE EXPIRED",
                        "Dear User \\nYour certificate is expired on " + c.getNotAfter()
                                + ".\\nPlease renew your certificate....\\n\\n\\nTHANK YOU");
            } else if (diff <= 10) {
                // certificate is about to expire in diff days
                System.out.println("certificate: " + certificate.getAliasname() + " is about to expire in " + diff + " days");
                emailUtil.sendEmailWithAttachment(certificate.getMail(), "ALERT!!CERTIFICATE EXPIRY",
                        "Dear User \nYour certificate is about to expire in " + diff
                                + " days! \nPlease renew your certificate....\n\n\nTHANK YOU",
                        "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer\\" + certificate.getAliasname() + ".cer");
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
            PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));

            Certificates m = certificatesRepository.getcertest(userForm.getAlias());
            PrivateKey pkm = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String dec= EncryptionDecryptionAES.decrypt(m.getCertificatetest(),pkm);
            X509Certificate certi = EncryptionDecryptionAES.convertToX509Cert(dec);

            RenewCertificate renewedCertificate = new RenewCertificate();
            long l = ((certi.getNotAfter().getTime() - (new Date(System.currentTimeMillis()).getTime())) / ((1000 * 60 * 60 * 24)));
            System.out.println("certificate will expire in: "+l+" days");
            if (l <= 0) {
                return "certificate expired, request for new one";
            } else if (l > 0 && l < 10) {
                X509Certificate c = renewedCertificate.renewCertificate(certi, pk, userForm.getRenewYears(), userForm.getAlias());
                Certificates s = renewedCertificate.saveFile(c, "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
                certificatesRepository.updateByAlias(userForm.getAlias(), s.getCertificatetest());
                emailUtil.sendEmailWithAttachment(m.getMail(),
                        "Renewed CERTIFICATE",
                        "Dear User, \nHere is your certificate \nIt is ready for installation to use....\n\n\nTHANK YOU",
                        "src\\main\\java\\com\\certificate\\learning\\digitalCertificate\\cer/" + userForm.getAlias() + ".cer");
                return "Certificate renewed successfully";
            } else {
                return "There is still time for renewal";
            }

        } catch (Exception e) {
            throw new CertificatesNotFoundException("Service: Certificate Not Found: The certificate you are tyring to renew is not found in db");
//            e.printStackTrace();
        } finally {
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    throw new CertificatesNotFoundException("Service: Certificate Not Found: The certificate you are tyring to renew is not found in db");
//                    e.printStackTrace();
                }
            }
        }
//        return res;
    }


    @Override
    public String validateCertificate(String alias) throws Exception {
        String res = "";
        Certificates certificates = certificatesRepository.findById(1).get();
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(certificates.getPrivatekey().getBytes("UTF-8"))));
        String dec= EncryptionDecryptionAES.decrypt(certificates.getCertificatetest(),pk);
        X509Certificate authCertCer = EncryptionDecryptionAES.convertToX509Cert(dec);
        X509Certificate toVerifyCer;
        try {
            Certificates m = certificatesRepository.getcertest(alias);
            KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
            PrivateKey pkm = keyFact2.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String decrypt= EncryptionDecryptionAES.decrypt(m.getCertificatetest(),pkm);
            toVerifyCer = EncryptionDecryptionAES.convertToX509Cert(decrypt);

        }catch (Exception e){
            throw new CertificatesNotFoundException("Service: Certificate Not found : certificate you are trying to validate is not found in db");
//            return "notFound";
        }

        ValidateCertificate v = new ValidateCertificate();

        boolean val=v.verifySignature(toVerifyCer,authCertCer);
        String exp=v.verifyExpiry(toVerifyCer);

        if(val==true)
        {
            if(exp.equals("expired"))
            {
                res="expired";
            } else if (exp.equals("notExpired")) {
                res="valid";
            }
        } else if(val==false){

            if(exp.equals("expired"))
            {
                res="invalidExpired";
            }
            else if(exp.equals("notExpired")){
                res="selfSigned";
            }

        }
        return res;
    }



    @Override
    public String getCertificateByAlias(String alias) throws Exception {
        // TODO Auto-generated method stub
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        Certificates m = certificatesRepository.getcertest(alias);
        PrivateKey pkm = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
        String dec= EncryptionDecryptionAES.decrypt(m.getCertificatetest(),pkm);
        X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);

        if(certificate==null) {
            throw new CertificatesNotFoundException("Service:: Certificate Not Found: The certifcate with "+alias+"  is not present in db");
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
    public String usercerts(String username) throws Exception {
        String res="";
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        List<Certificates> list = certificatesRepository.getCertByUser(username);
        if(list.size()==0)
            return "no certificates yet";
        for(Certificates m : list){
            ArrayList<String> temp = new ArrayList<>();
            PrivateKey pkm = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(m.getPrivatekey().getBytes("UTF-8"))));
            String dec= EncryptionDecryptionAES.decrypt(m.getCertificatetest(),pkm);
            X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);
            res += m.getAliasname()+","+certificate.getNotBefore().toGMTString()+","+certificate.getNotAfter().toGMTString()+"\n";

        }
        return res.substring(0,res.length()-1);

    }
}
