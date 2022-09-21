package com.certificate.learning.digitalCertificate.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class CertificatesException {

    // handles specific exception
    @ExceptionHandler(value = CertificatesNotFoundException.class)
    public ResponseEntity<String> certificatesNotFound(CertificatesNotFoundException e){
        return new ResponseEntity<String>("Certifcate Not found...",HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = LoginException.class)
    public ResponseEntity<String> loginException (LoginException e){
        return new ResponseEntity<String>("Login Exception",HttpStatus.NOT_FOUND);
    }
}
