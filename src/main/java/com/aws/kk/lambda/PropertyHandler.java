package com.aws.kk.lambda;

import java.util.Properties;

public class PropertyHandler {
	//Allowed Properties
	
	public static final String CFG_SAML_NAMEID = "saml_nameid";
	public static final String CFG_SAML_NAMEID_FORMAT = "saml_nameid_format";
	public static final String CFG_SAML_AUDIENCE_RESTRICTION = "saml_audience_restriction";
	public static final String CFG_SAML_ISSUER = "saml_issuer";
	public static final String CFG_SAML_AUTHNCONTEXT_PREVIUOUS_AUTHENTICATION = "saml_session_authentication";
	
	public static final String CFG_OA2_TOKEN_ENDPOINT = "oa2_token_endpoint";
	public static final String CFG_OA2_ENDPOINT_HOST = "oa2_endpoint_host";
	public static final String CFG_OA2_CLIENT_ID = "oa2_client_id";
	public static final String CFG_OAUTH_CLIENT_PASSWORD = "oa2_client_password";
	
	public static final String CFG_AWS_BUCKET = "aws_bucket";
	public static final String CFG_AWS_KEY_FILE = "aws_key_file";
	public static final String CFG_AWS_CERT_FILE = "aws_cert_file";
	public static final String CFG_AWS_NLB_URL = "aws_nlb_url";
	public static final String CFG_AWS_NLB_HOST = "aws_nlb_host";
	public static final String CFG_LOGGING_ENABLED = "aws_logging_enabled";
	public static final String CFG_LOG_TO_SCREEN = "aws_logs_to_screen";	
	
	public static void checkPropertySet(Properties props, String propName) throws MissingPropertyException {
		if(getValue(props,propName) == null)
			throw new MissingPropertyException(propName);
	}
	
	public static String getValue(Properties props,  String propName) {
		return props.getProperty(propName);
	}
	
	public static String getValue(Properties props,  String propName, String defaultValue) {
		return props.getProperty(propName, defaultValue);
	}
	
	
}
