package com.certificate.learning.digitalCertificate;

import com.certificate.learning.digitalCertificate.bean.Certificates;
import com.certificate.learning.digitalCertificate.bean.RenewForm;
import com.certificate.learning.digitalCertificate.bean.UserForm;
import com.certificate.learning.digitalCertificate.repository.CertificatesRepository;
import com.certificate.learning.digitalCertificate.service.CertificateService;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class DigitalCertificateApplicationTests {

	@Autowired
	private CertificateService certificateService;

	@Autowired
	private CertificatesRepository certificatesRepository;

	@Test
	void testvalidate() throws Exception {
		String validity=certificateService.validateCertificate("signed");
		assertEquals(validity,"valid");
	}
	//Check This with any signed cert in ur db

	@Test
	void testUserCerts() throws Exception {
		String certList = certificateService.usercerts("CaAuthority");
		String [] certsArray = certList.split("\n");
		assertEquals(certsArray.length,1);
	}
	//Check This with CaAuthority of ur db who has only one cert

	@Test
	void testRenewal(){
		RenewForm renewForm = new RenewForm();
		renewForm.setAlias("ssexp");
		renewForm.setRenewYears(2);
		String renewal = certificateService.renewCertificate(renewForm);
		assertEquals(renewal,"certificate expired, request for new one");
	}
	//Check This with any expired certificate in ur db


//In all the below generate cases..we are comparing generated certificate and the one stored in repository
	@Test
	void testGenerateSS() throws Exception {
		UserForm userForm = new UserForm();
		userForm.setAlias("sstest3");
		userForm.setCn("ssCert");
		userForm.setCountry("India");
		userForm.setEmail("abc@gmail.com");
		userForm.setName("pooja");
		userForm.setOrganization("Telstra");
		userForm.setState("Ts");
		userForm.setLocality("Hyd");
		String Cert = certificateService.generateSelfSignedCertificate(userForm);
		Certificates cert = certificatesRepository.getcertest("sstest3");
		int id = cert.getId();

		KeyFactory keyFact = KeyFactory.getInstance("RSA");
		PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(cert.getPrivatekey().getBytes("UTF-8"))));
		String dec= EncryptionDecryptionAES.decrypt(cert.getCertificatetest(),pk);
		X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);
		String CertRepo = new String(Base64.encode(certificate.getEncoded()));
		certificatesRepository.deleteById(id);
		assertEquals(Cert,CertRepo);


	}

	@Test
	void testGenerateCA() throws Exception {
		UserForm userForm = new UserForm();
		userForm.setAlias("caTest");
		userForm.setCn("caCert");
		userForm.setCountry("India");
		userForm.setEmail("abc@gmail.com");
		userForm.setName("pooja");
		userForm.setOrganization("Telstra");
		userForm.setState("Ts");
		userForm.setLocality("Hyd");
		String Cert = certificateService.generateCaSignedCertificate(userForm);
		Certificates cert = certificatesRepository.getcertest("caTest");
		int id = cert.getId();

		KeyFactory keyFact = KeyFactory.getInstance("RSA");
		PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(cert.getPrivatekey().getBytes("UTF-8"))));
		String dec= EncryptionDecryptionAES.decrypt(cert.getCertificatetest(),pk);
		X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);
		String CertRepo = new String(Base64.encode(certificate.getEncoded()));
		certificatesRepository.deleteById(id);
		assertEquals(Cert,CertRepo);


	}

	@Test
	void testGenerateSigned() throws Exception {
		UserForm userForm = new UserForm();
		userForm.setAlias("signedTest");
		userForm.setCn("signedCert");
		userForm.setCountry("India");
		userForm.setEmail("abc@gmail.com");
		userForm.setName("pooja");
		userForm.setOrganization("Telstra");
		userForm.setState("Ts");
		userForm.setLocality("Hyd");
		String Cert = certificateService.generateSignedCertificate(userForm);
		Certificates cert = certificatesRepository.getcertest("signedTest");
		int id = cert.getId();

		KeyFactory keyFact = KeyFactory.getInstance("RSA");
		PrivateKey pk = keyFact.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(cert.getPrivatekey().getBytes("UTF-8"))));
		String dec= EncryptionDecryptionAES.decrypt(cert.getCertificatetest(),pk);
		X509Certificate certificate = EncryptionDecryptionAES.convertToX509Cert(dec);
		String CertRepo = new String(Base64.encode(certificate.getEncoded()));
		certificatesRepository.deleteById(id);
		assertEquals(Cert,CertRepo);


	}

}
