package com.aws.kk.lambda;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.runtime.Context; 

import org.json.simple.JSONObject;
import org.opensaml.xml.ConfigurationException;
import org.json.simple.parser.JSONParser;

public class SAPOAuthHandler implements RequestStreamHandler{

	JSONParser parser = new JSONParser();
	Properties configProps = new Properties();
	ExecutionLogger logger;
	
	@SuppressWarnings("unchecked")
	public void handleRequest(InputStream input, OutputStream output, Context context) throws IOException {
		
		BufferedReader inputReader = new BufferedReader(new InputStreamReader(input));
		
		JSONObject responseJson = new JSONObject();
		String responseCode = "200";
		//configProps.putAll(System.getenv());
		
		try {
			JSONObject responseBody = new JSONObject();
			
			//Get the event object from input
			JSONObject event = (JSONObject)parser.parse(inputReader);
			String bodyString = (String) event.get("body");
			JSONObject body = (JSONObject)parser.parse(bodyString);
			
			//Get the properties from event body
			String action = (String) body.get("action");
			String scope = (String) body.get("scope");
		
			JSONObject propsJSON = (JSONObject)body.get("properties");
			Set<String> propKeys = propsJSON.keySet();
			for (String p:propKeys) {
				configProps.setProperty(p, (String) propsJSON.get(p)); 
			}
			
			logger = new ExecutionLogger(context, configProps);
			String nameid = getNameId(event);
			configProps.setProperty("saml_nameid", nameid);
	
			logger.log("Step 0: Action is " + action);
			if(action.equals("metadata")) {
				logger.log("Step 1: Metada action requested");
				responseBody.put("metadataxml", getMetaDataXML());
			}else if(action.equals("accessToken")) {
				logger.log("Step 1: AccessToken action requested");
				responseBody.put("accessToken", getAccessToken(scope,nameid));
				responseJson.put("isBase64Encoded", false);
			}
			
			responseJson.put("statusCode", responseCode);
			responseJson.put("body", responseBody.toString());  
			
		}catch(Exception ex) {
			//logger.log("Kaput! Error in handling this request: ",ex);
			responseJson.put("statusCode", "400");
            responseJson.put("exception", ex);
		}
		
		 OutputStreamWriter writer = new OutputStreamWriter(output, "UTF-8");
	     writer.write(responseJson.toJSONString());  
	     writer.close();

	}
	
	private String getAccessToken(String scope,String nameid) throws ConfigurationException, NoSuchAlgorithmException, KeyManagementException, AccessTokenException {
		logger.log("...Entering getAccessToken method");
		String accessToken = null;
		LocalSamlTokenFactory localSAMLTokenFactory = (LocalSamlTokenFactory) LocalSamlTokenFactory.getInstance(configProps,logger);
		//Ignore SSL errors
		logger.log("...Setting ignore SSL errors");
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}
			public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
			}
			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}
		}};
		
		logger.log("...Allowing Self signed certs");
		// Trust all certs - even self signed
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		
		logger.log("...Trusting the AWS NLB");
		// Allow the cert CN be different than the NLB
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
			    new javax.net.ssl.HostnameVerifier(){
			 
			        public boolean verify(String hostname,
			                javax.net.ssl.SSLSession sslSession) {
			            if (hostname.equals(PropertyHandler.getValue(configProps, PropertyHandler.CFG_AWS_NLB_HOST))) {
			                return true;
			            }
			            return false;
			        }
	    });
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		
		logger.log("...Calling OAuth2SAML2AccessToken(localSAMLTokenFactory)");
		OAuth2SAML2AccessToken atf = new OAuth2SAML2AccessToken(localSAMLTokenFactory);

		logger.log("...getting the access token");
		accessToken = atf.getAccessToken(configProps, scope);
		
		return accessToken;
				
	}
	
	private String getMetaDataXML() {
		logger.log("...Entering getMetaDataXML method");
		TrustData td = new TrustData(configProps,logger);
		return td.getMetadaXML();
	}
	
	private String getNameId(JSONObject inJson) {
		logger.log("...Try to get name ID from request context");
		String returnValue = "";
		try {
			JSONObject requestContext = (JSONObject) getChildJson(inJson,"requestContext");
			logger.log("....received requestContext");
			JSONObject authorizer = (JSONObject) getChildJson(requestContext,"authorizer");
			logger.log("....received authorizer");
			JSONObject claims = (JSONObject) getChildJson(authorizer,"claims");
			logger.log("....received claims");
			String identitiesAsString = (String) claims.get("identities");
			logger.log("....received identities string" + identitiesAsString );
			JSONObject identities = (JSONObject)parser.parse(identitiesAsString);
			logger.log("....received identities");
 			returnValue = (String) identities.get("userId");
 			logger.log("....received userId from identities" +  returnValue );
		}catch(Exception e) {
			logger.log("error getting nameid " + e.getMessage());
		}
		return returnValue;
	}
	
	private JSONObject getChildJson(JSONObject inJson, String nodeName) {
		JSONObject childJson = (JSONObject) inJson.get(nodeName); 
		return childJson;
	}
	
	
}
