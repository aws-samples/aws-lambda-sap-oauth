package com.aws.sap.sample.lambda.sap.oauth;

import java.util.Properties;

public interface SamlTokenFactory {
	public abstract String getSamlAssertion(Properties cfgProperties) throws SAMLException;

}
