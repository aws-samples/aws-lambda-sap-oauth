package com.aws.sap.sample.lambda.sap.oauth;

public class MissingPropertyException extends Exception {
	public MissingPropertyException(String missingProperty) {
		super("Missing property: " + missingProperty);
	}
}
