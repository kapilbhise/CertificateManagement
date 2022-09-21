package com.certificate.learning.digitalCertificate.bean;


import org.springframework.stereotype.Component;

import javax.persistence.Entity;
import javax.persistence.Id;

@Component
@Entity
public class Certificates {
    @Id
    private int id;
    private String aliasname;
    private String caflag;
    private String certificatetest;
    private String privatekey;
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