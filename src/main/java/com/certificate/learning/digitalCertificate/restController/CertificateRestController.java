package com.certificate.learning.digitalCertificate.restController;

import com.certificate.learning.digitalCertificate.bean.LoginForm;
import com.certificate.learning.digitalCertificate.bean.RenewForm;
import com.certificate.learning.digitalCertificate.bean.UserForm;
import com.certificate.learning.digitalCertificate.exception.CertificatesNotFoundException;
import com.certificate.learning.digitalCertificate.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.login.LoginException;
import java.security.cert.CertificateEncodingException;

@RestController
@CrossOrigin(origins="*")
public class CertificateRestController {
    @Autowired
    private CertificateService certificateService;


    @PostMapping("/ss")
    public ResponseEntity<String> ssCertificate(@RequestBody UserForm userForm) throws Exception {
//        certificateService.generateSelfSignedCertificate(userForm);
//        return new ResponseEntity<>("Self Signed Certificate is created", HttpStatus.OK);
        try {
            String s=certificateService.generateSelfSignedCertificate(userForm);
            return new ResponseEntity<>(s, HttpStatus.OK);
        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }


    @PostMapping("/ca")
    public ResponseEntity<String> caSignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
//    	certificateService.generateCaSignedCertificate(userForm);
//      return new ResponseEntity<>("CA Signed Certificate is created", HttpStatus.OK);
        try {
            String s=certificateService.generateCaSignedCertificate(userForm);
            return new ResponseEntity<>(s, HttpStatus.OK);

        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping("/signed")
    public ResponseEntity<String> SignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
//        certificateService.generateSignedCertificate(userForm);
//        return new ResponseEntity<>("Signed Certificate is created", HttpStatus.OK);
        try {
            String s=certificateService.generateSignedCertificate(userForm);
            return new ResponseEntity<>(s, HttpStatus.OK);
        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }

    }

    @PutMapping("/renew")
    public ResponseEntity<String> CertificateRenewal(@RequestBody RenewForm userForm) throws Exception {
        try {
            String res =certificateService.renewCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch (CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/validate/{alias}")
    public ResponseEntity<String> validateCertificateById(@PathVariable("alias") String alias) throws Exception {
        try {
            String validity=certificateService.validateCertificate(alias);
            if(validity.equals("expired"))
            {
                return new ResponseEntity<>("--INVALID CERTIFICATE--Your certificate has expired",HttpStatus.OK);
            }
            else if(validity.equals("invalidExpired"))
            {
                return new ResponseEntity<>("--INVALID CERTIFICATE--Your certificate is Self-Signed and expired",HttpStatus.OK);
            }
            else if(validity.equals("selfSigned"))
            {
                return new ResponseEntity<>("--INVALID CERTIFICATE--Your certificate is a Self-Signed certificate",HttpStatus.OK);
            }
            else if(validity.equals("valid")) {
                return new ResponseEntity<>("--VALID CERTIFICATE--", HttpStatus.OK);
            }

        }
        catch (CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
//        throw new CertificatesNotFoundException("Hey there certifcicate is not availabe in db");
        return new ResponseEntity<>("--CERTIFICATE NOT FOUND--No Certificate found with aliasname : "+alias,HttpStatus.NOT_FOUND);
    }





    @GetMapping("/certificates/{alias}")
    public ResponseEntity<String> getCertificateByAlias(@PathVariable("alias") String alias,  Model model) throws CertificateEncodingException {
        try {
            String s;
            s= certificateService.getCertificateByAlias(alias);
            if(s.isEmpty()) {
                throw new CertificatesNotFoundException("Certificate Not Found: There is no certificate with "+alias+ " as an aliasname in db");
            }
            else {
                return new ResponseEntity<String>(s, HttpStatus.OK);
            }

        }
        catch (Exception e) {
            return new ResponseEntity<>("Controller: "+"Certificate Not Found: There is no certificate with "+alias+ " as an aliasname in db ",HttpStatus.NOT_FOUND);
        }

    }


    @PostMapping("/login")
    public ResponseEntity<String> loginUsers(@RequestBody LoginForm loginform)  {
        try{
            return ResponseEntity.status(HttpStatus.OK).body(certificateService.loginUser(loginform));
        }catch (LoginException e){
            if(e.getMessage().equals("no such user"))
                return new ResponseEntity<String>("User Not Found",HttpStatus.NOT_FOUND);
            else if(e.getMessage().equals("wrong password"))
                return new ResponseEntity<String>("Check Your Password",HttpStatus.FORBIDDEN);

        }
        return new ResponseEntity<String>("Login Exception..",HttpStatus.NOT_FOUND);

    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody LoginForm loginform) throws LoginException {
        try{
            certificateService.saveUser(loginform);
            return ResponseEntity.status(HttpStatus.OK).body("user registered");
        }catch (LoginException e){
            return new ResponseEntity<String>("User Exists...try login",HttpStatus.BAD_REQUEST);
        }
        //return new ResponseEntity<String>("Login Exception..",HttpStatus.NOT_FOUND);
    }


    @GetMapping("/certs/{name}")
    public ResponseEntity<String> usercerts(@PathVariable("name") String name) throws Exception {
        return new ResponseEntity<>(certificateService.usercerts(name),HttpStatus.OK);
    }


}
