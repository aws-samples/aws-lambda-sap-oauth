package com.aws.sap.sample.lambda.sap.oauth;

public class AccessTokenException extends Exception {

	public AccessTokenException(Exception ex) {
		super(ex);
	}

	public AccessTokenException(String message) {
		super(message);
	}
}