package com.certificate.learning.digitalCertificate.restController;

import com.certificate.learning.digitalCertificate.bean.RenewForm;
import com.certificate.learning.digitalCertificate.bean.UserForm;
import com.certificate.learning.digitalCertificate.exception.CertificatesNotFoundException;
import com.certificate.learning.digitalCertificate.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateEncodingException;

@RestController
@CrossOrigin("http://localhost:3000")
public class CertificateRestController {
    @Autowired
    private CertificateService certificateService;




    @PostMapping("/ss")
    public ResponseEntity<String> ssCertificate(@RequestBody UserForm userForm) throws Exception {
        try {
            String res=certificateService.generateSelfSignedCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }


    @PostMapping("/ca")
    public ResponseEntity<String> caSignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
        try {
            String res=certificateService.generateCaSignedCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);

        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }


    @PostMapping("/signed")
    public ResponseEntity<String> SignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
        try {
            String res =certificateService.generateSignedCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        catch(CertificatesNotFoundException e) {
            return new ResponseEntity<>("Controller: "+e.getMessage(), HttpStatus.NOT_FOUND);
        }

    }


    @PostMapping("/unsigned")
    public ResponseEntity<String> UnsignedCertGeneration(@RequestBody UserForm userForm) throws Exception {
        try {
            String res =certificateService.generateUnsignedCertificate(userForm);
            return new ResponseEntity<>(res, HttpStatus.OK);
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
            return new ResponseEntity<>("Controller: "+e.getMessage(),HttpStatus.NOT_FOUND);
        }

    }



    @GetMapping("/certs/{name}")
    public ResponseEntity<String> usercerts(@PathVariable("name") String name) throws Exception {
        return new ResponseEntity<>(certificateService.usercerts(name),HttpStatus.OK);
    }





}
