package com.certificate.learning.digitalCertificate;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Hex.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.crypto.*;

import static org.hibernate.validator.internal.util.Contracts.assertTrue;

public class EncryptionDecryptionAES {
    //static final private String orginalMessage = "MIICSjCCAbOgAwIBAgIGAYMyid5OMA0GCSqGSIb3DQEBCwUAMF4xDTALBgNVBAMMBGNhIE8xCjAIBgNVBAcMAUwxCzAJBgNVBAgMAmlsMQowCAYDVQQGEwFjMSgwJgYJKoZIhvcNAQkBFhljYWNlcnRpZmljYXRlQGFiYy5pYm0uY29tMB4XDTIyMDkxMTE2MzAzOVoXDTMyMDkwOTE2MzAzOVowXjENMAsGA1UEAwwEY2EgTzEKMAgGA1UEBwwBTDELMAkGA1UECAwCaWwxCjAIBgNVBAYTAWMxKDAmBgkqhkiG9w0BCQEWGWNhY2VydGlmaWNhdGVAYWJjLmlibS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANVbGG50m9gTJpyqEQ4Fd+bXXLmBwbN7Le1gii8XmKbB5pNTKrMby/M9K68ugokqUhNSL6lOK971+qOjhiu51NOMqjo1HmDp30PsRoSQqSW3qWC8ZpiuekVzH+TIxPhOkzBg950Pz9ez+rjPDPc7IIC2zdBkTh8Pv647s3TCzG4RAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAZ9T4mmQVM8gJ2Ppfj8prlA5XEahnfW6Pp1w3vhSnsEe2JdgUoX7k6YaKFBty5EsVGJ38+aEhw3RNNXN4GaiSYmWPHUccqHoe/j5V4u4O/3nTlr/gA7xyGnIZ/WlNU6pkANZDL5hjiZGuhyX7kX/Tg/AraQLEQmp5H+P4UULFJwQ=";
    static Cipher cipher;

    static {
        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(String plaintext,PublicKey puk) throws Exception{
        //Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, puk);
        byte[] bytes = plaintext.getBytes("UTF-8");
        byte[] encrypted = blockCipher(bytes,Cipher.ENCRYPT_MODE);
        char[] encryptedTranspherable = Hex.encodeHex(encrypted);
        return new String(encryptedTranspherable);
    }
    public static String decrypt(String encrypted,PrivateKey pk) throws Exception{
        //Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pk);
        byte[] bts = Hex.decodeHex(encrypted.toCharArray());
        byte[] decrypted = blockCipher(bts,Cipher.DECRYPT_MODE);
        return new String(decrypted,"UTF-8");
    }
    private static byte[] blockCipher(byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        //Cipher cipher=Cipher.getInstance("RSA");
        byte[] scrambled = new byte[0];

        // toReturn will hold the total result
        byte[] toReturn = new byte[0];
        // if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;

        // another buffer. this one will hold the bytes that have to be modified in this step
        byte[] buffer = new byte[length];

        for (int i=0; i< bytes.length; i++){

            // if we filled our buffer array we have our block ready for de- or encryption
            if ((i > 0) && (i % length == 0)){
                //execute the operation
                scrambled = cipher.doFinal(buffer);
                // add the result to our total result.
                toReturn = append(toReturn,scrambled);
                // here we calculate the length of the next buffer required
                int newlength = length;

                // if newlength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + length > bytes.length) {
                    newlength = bytes.length - i;
                }
                // clean the buffer array
                buffer = new byte[newlength];
            }
            // copy byte into our buffer.
            buffer[i%length] = bytes[i];
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer);

        // final step before we can return the modified data.
        toReturn = append(toReturn,scrambled);

        return toReturn;
    }
    private static byte[] append(byte[] prefix, byte[] suffix){
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i=0; i< prefix.length; i++){
            toReturn[i] = prefix[i];
        }
        for (int i=0; i< suffix.length; i++){
            toReturn[i+prefix.length] = suffix[i];
        }
        return toReturn;
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getDecoder().decode(certificateString);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }


}
