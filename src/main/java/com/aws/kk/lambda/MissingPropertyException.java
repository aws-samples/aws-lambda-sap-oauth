package com.aws.kk.lambda;

public class MissingPropertyException extends Exception {
	public MissingPropertyException(String missingProperty) {
		super("Missing property: " + missingProperty);
	}
}