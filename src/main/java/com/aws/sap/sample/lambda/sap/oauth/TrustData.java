package com.aws.sap.sample.lambda.sap.oauth;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;

import org.opensaml.xml.util.Base64;

public class TrustData {
	Properties cfg;
	ExecutionLogger logger;

	public TrustData(Properties cfg, ExecutionLogger logger) {
		this.cfg = cfg;
		this.logger = logger;
	}
	
	private X509Certificate getSigningCertificate()
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
		
		KeyStoreHandler _KeyStoreHandler = new S3KeyStoreHandler();
		Map<String, Object> keys = _KeyStoreHandler.getKeys(cfg);
		return (X509Certificate)keys.get(KeyStoreHandler.KS_PUBLIC_KEY);
	}
	
	public String getMetadaXML() {
		String md = "";
		try {
			X509Certificate[] certs = new X509Certificate[] { getSigningCertificate() };
			String mdTemplate = "<?xml version='1.0' encoding='UTF-8'?><m:EntityDescriptor entityID='$$$ISSUER$$$' xmlns:m='urn:oasis:names:tc:SAML:2.0:metadata'><m:RoleDescriptor xsi:type='fed:SecurityTokenServiceType' xmlns:fed='http://docs.oasis-open.org/wsfed/federation/200706' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' protocolSupportEnumeration='http://docs.oasis-open.org/ws-sx/ws-trust/200512 http://schemas.xmlsoap.org/ws/2005/02/trust http://docs.oasis-open.org/wsfed/federation/200706'><m:KeyDescriptor use='signing'><ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:X509Data><ds:X509Certificate>$$$CERT$$$</ds:X509Certificate></ds:X509Data></ds:KeyInfo></m:KeyDescriptor><fed:TokenTypesOffered><fed:TokenType Uri='urn:oasis:names:tc:SAML:1.0:assertion'/></fed:TokenTypesOffered></m:RoleDescriptor></m:EntityDescriptor>";
			md = mdTemplate.replace("$$$ISSUER$$$", PropertyHandler.getValue(cfg, PropertyHandler.CFG_SAML_ISSUER));
			String certB64;
			certB64 = Base64.encodeBytes((certs[certs.length - 1].getEncoded()));
			md = md.replace("$$$CERT$$$", certB64);
			
		} catch (Exception ex) {
			logger.log("Kaput! Error in getting metadata : " + ex);
		}
		return md;
	}
	
}
