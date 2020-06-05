package com.aws.sap.sample.lambda.sap.oauth;

import java.io.IOException;
import java.util.Properties;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import java.security.UnrecoverableKeyException;
import java.security.KeyStoreException;

public interface KeyStoreHandler {

  public static final String KS_PRIVATE_KEY = "private";
	public static final String KS_PUBLIC_KEY = "public";

  public Map<String,Object> getKeys(Properties props) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException;

}