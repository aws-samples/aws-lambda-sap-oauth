package com.aws.kk.lambda;

public class AccessTokenException extends Exception {

	public AccessTokenException(Exception ex) {
		super(ex);
	}

	public AccessTokenException(String message) {
		super(message);
	}
}