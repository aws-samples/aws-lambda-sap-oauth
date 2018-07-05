package com.aws.kk.lambda;

import java.util.Properties;

public interface SamlTokenFactory {
	public abstract String getSamlAssertion(Properties cfgProperties) throws SAMLException;

}
