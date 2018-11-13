package com.aws.sap.sample.lambda.sap.oauth;

import java.io.IOException;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import java.security.UnrecoverableKeyException;
import java.security.KeyStoreException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.KeyFactory;

import org.apache.commons.io.IOUtils;
import java.io.FileInputStream;
import java.io.File;
import org.apache.commons.codec.binary.Base64;

import java.security.spec.PKCS8EncodedKeySpec;

import java.security.cert.CertificateFactory;

public class TestKeyStoreHandler implements KeyStoreHandler {

  public Map<String,Object> getKeys(Properties props) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
    
    Map<String,Object> keys = new HashMap<String,Object>();
		String keyfile  = PropertyHandler.getValue(props, PropertyHandler.CFG_AWS_KEY_FILE);
    String certfile  = PropertyHandler.getValue(props, PropertyHandler.CFG_AWS_CERT_FILE);
    
    keys.put(KS_PRIVATE_KEY, getPrivateKey(keyfile) );
		keys.put(KS_PUBLIC_KEY, getPublicKey(certfile) );
		
    return keys;
  }

  private static PrivateKey getPrivateKey(String fileName) {
		PrivateKey privateKey = null;
		try {
				FileInputStream fisTargetFile = new FileInputStream(new File("src/test/resources/" + fileName));
				String privKeyPEM = IOUtils.toString(fisTargetFile, "UTF-8");

		    privKeyPEM = privKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
		    privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
		    Base64 b64 = new Base64();
		    byte [] decoded = b64.decode(privKeyPEM);
		    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    privateKey = kf.generatePrivate(spec);
		    
		} catch (Exception e) {
		    System.out.println(e.getMessage());
		}
		return privateKey;

	}
	
	private static X509Certificate getPublicKey(String fileName) {

			X509Certificate crt = null;

			try {
				FileInputStream fisTargetFile = new FileInputStream(new File("src/test/resources/" + fileName));
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				crt = (X509Certificate)cf.generateCertificate(fisTargetFile);
			} catch (Exception e) {
			    System.out.println(e.getMessage());
			}
			
			return crt;
	}

}