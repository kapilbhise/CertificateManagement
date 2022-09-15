package com.certificate.learning.digitalCertificate.service;


import com.certificate.learning.digitalCertificate.bean.*;

import javax.security.auth.login.LoginException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public interface CertificateService {
    public String generateSelfSignedCertificate(UserForm userForm) throws Exception;
    public String generateCaSignedCertificate(UserForm userForm) throws Exception;
    public String generateSignedCertificate(UserForm userForm);
    public String generateUnsignedCertificate(UserForm userForm) throws Exception;
    //public void notifyExpiry() throws Exception;

    public String renewCertificate(RenewForm userForm);

    public String validateCertificate(String alias) throws Exception;
    public String getCertificateByAlias(String alias) throws Exception;
    public String loginUser(LoginForm loginform) throws LoginException;

    public void saveUser(LoginForm loginForm) throws LoginException;
    public String usercerts(String username) throws Exception;

}
