package com.aws.kk.lambda;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Properties;


public class OAuth2SAML2AccessToken {

	public static boolean sslIgnoreSet = false;
	SamlTokenFactory stf;

	public OAuth2SAML2AccessToken(SamlTokenFactory stf) {
		this.stf = stf;
	}
	
	public String getAccessToken(Properties _cfg, String scope) throws AccessTokenException {
		try {
			PropertyHandler.checkPropertySet(_cfg, PropertyHandler.CFG_AWS_NLB_URL);
			PropertyHandler.checkPropertySet(_cfg, PropertyHandler.CFG_OA2_TOKEN_ENDPOINT);
			PropertyHandler.checkPropertySet(_cfg, PropertyHandler.CFG_OA2_CLIENT_ID);
			PropertyHandler.checkPropertySet(_cfg, PropertyHandler.CFG_OAUTH_CLIENT_PASSWORD);
		
			String assertionString = stf.getSamlAssertion(_cfg);
			System.out.println("asserstion string is: " + assertionString);
			
			String postUrl =  PropertyHandler.getValue(_cfg, PropertyHandler.CFG_AWS_NLB_URL);
			System.out.println(".....URL to post is " + postUrl );
			String oa2Username =  PropertyHandler.getValue(_cfg, PropertyHandler.CFG_OA2_CLIENT_ID);
			String oa2Password =  PropertyHandler.getValue(_cfg, PropertyHandler.CFG_OAUTH_CLIENT_PASSWORD);
		
			String b64Data = URLEncoder.encode(org.opensaml.xml.util.Base64.encodeBytes(assertionString.getBytes()),
					"UTF-8");
			
			System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
			HttpURLConnection con = (HttpURLConnection) new URL(postUrl).openConnection();
			//Set the Host header to the end point host instead of the AWS NLB
			con.setRequestProperty("Host",PropertyHandler.getValue(_cfg, PropertyHandler.CFG_OA2_ENDPOINT_HOST) );
						
			String data = "client_id=" + oa2Username + "&scope=" + scope
					+ "&grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&assertion=" + b64Data;
			con.addRequestProperty("Authorization",
					"Basic " + org.opensaml.xml.util.Base64.encodeBytes((oa2Username + ":" + oa2Password).getBytes()));
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestProperty("Cookie", "");
			con.setRequestMethod("POST");
			OutputStreamWriter wr = new OutputStreamWriter(con.getOutputStream());
			wr.write(data);
			wr.flush();

			int respCode = con.getResponseCode();
			if (respCode != 200) {
				byte[] res = readData(con.getErrorStream());
				throw new AccessTokenException(new String(res));
			} else {
				byte[] res = readData(con.getInputStream());
				return new String(res);
			}

		} catch (Exception ex) {
			throw new AccessTokenException(ex);
		}
	}

	private byte[] readData(InputStream is) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int dataElement;
		while ((dataElement = is.read()) != -1) {
			bos.write(dataElement);
		}
		byte[] inData = bos.toByteArray();
		return inData;
	}
}
