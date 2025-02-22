package com.certificate.learning.digitalCertificate.bean;


import org.springframework.stereotype.Component;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.Size;

import java.security.cert.Certificate;

@Component
@Entity
public class Certificates {


    @Id
    @GeneratedValue(strategy=GenerationType.AUTO)
    private int id;
    private String aliasname;
    private String caflag;
    
    @Size(max = 4000)
    private String certificatetest;
    @Size(max = 4000)
    private String privatekey;
    @Size(max = 4000)
    private String publickey;
    private String mail;
    private String username;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getMail() {
        return mail;
    }

    public void setMail(String mail) {
        this.mail = mail;
    }

    public String getAliasname() {
        return aliasname;
    }

    public void setAliasname(String aliasname) {
        this.aliasname = aliasname;
    }

    public String getCaflag() {
        return caflag;
    }

    public void setCaflag(String caflag) {
        this.caflag = caflag;
    }

    public String getCertificatetest() {
        return certificatetest;
    }

    public void setCertificatetest(String certificatetest) {
        this.certificatetest = certificatetest;
    }

    public String getPrivatekey() {
        return privatekey;
    }

    public void setPrivatekey(String privatekey) {
        this.privatekey = privatekey;
    }

    public String getPublickey() {
        return publickey;
    }

    public void setPublickey(String publickey) {
        this.publickey = publickey;
    }
}