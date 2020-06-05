package com.aws.sap.sample.lambda.sap.oauth;

import java.io.IOException;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.UnrecoverableKeyException;
import java.security.KeyStoreException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.KeyFactory;

import java.util.Properties;
import java.util.Map;
import java.util.HashMap;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.codec.binary.Base64;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class S3KeyStoreHandler implements KeyStoreHandler {

	public Map<String,Object> getKeys(Properties props) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		Map<String,Object> keys = new HashMap<String,Object>();
		
		String bucket = PropertyHandler.getValue(props, PropertyHandler.CFG_AWS_BUCKET);
		String keyfile  = PropertyHandler.getValue(props, PropertyHandler.CFG_AWS_KEY_FILE);
		String certfile  = PropertyHandler.getValue(props, PropertyHandler.CFG_AWS_CERT_FILE);
		
		PrivateKey privateKey = null;
		try {
			privateKey = (PrivateKey) getPrivateKey(bucket,keyfile);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		X509Certificate pubKey = (X509Certificate) getPublicKey(bucket,certfile);
			
		keys.put(KS_PRIVATE_KEY, privateKey );
		keys.put(KS_PUBLIC_KEY, pubKey );
	
		return keys;
	}
	
	private static PrivateKey getPrivateKey(String bucket, String fileName) throws NoSuchAlgorithmException, InvalidKeySpecException {
		final AmazonS3 s3 = AmazonS3ClientBuilder.defaultClient();
		PrivateKey privateKey = null;
		try {
		    S3Object o = s3.getObject(bucket,fileName);
		    S3ObjectInputStream s3is = o.getObjectContent();
		    StringWriter writer = new StringWriter();
		    IOUtils.copy(s3is, writer, "UTF-8");
		    String privKeyPEM = writer.toString();
		    s3is.close();
		    privKeyPEM = privKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
		    privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
		    Base64 b64 = new Base64();
		    byte [] decoded = b64.decode(privKeyPEM);
		    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		    //X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    privateKey = kf.generatePrivate(spec);
		    //System.out.println("File content is " +  theString);
		    
		} catch (AmazonServiceException e) {
		    System.out.println(e.getErrorMessage());
		} catch (IOException e) {
		    System.out.println(e.getMessage());
		} catch (InvalidKeySpecException e) {
			System.out.println(e.getMessage());
		}
		return privateKey;

	}
	
	private static X509Certificate getPublicKey(String bucket, String fileName) throws IOException, CertificateException {
			final AmazonS3 s3 = AmazonS3ClientBuilder.defaultClient();
			X509Certificate crt = null;
			S3ObjectInputStream s3is = null;
			try {
				S3Object o = s3.getObject(bucket,fileName);
				s3is = o.getObjectContent();
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				crt = (X509Certificate)cf.generateCertificate(s3is);
			} catch (AmazonServiceException e) {
			    System.out.println(e.getErrorMessage());
			} finally {
				s3is.close();
			}
			
			return crt;
	}
}