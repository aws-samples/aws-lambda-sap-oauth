package com.aws.sap.sample.lambda.sap.oauth;

public class SAMLException  extends Exception {
	
	public SAMLException(Exception rootException) {
		super(rootException);
	}

	public SAMLException(Error rootException) {
		super(rootException);
	}

	public SAMLException(String errorString) {
		super(errorString);
	}

}
