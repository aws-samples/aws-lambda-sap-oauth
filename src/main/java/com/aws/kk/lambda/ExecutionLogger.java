package com.aws.kk.lambda;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Properties;
import com.amazonaws.services.lambda.runtime.Context; 
import com.amazonaws.services.lambda.runtime.LambdaLogger;

public class ExecutionLogger {
	private LambdaLogger logger;
	private String isLoggingEnabled = "true";
	private String isLogToScreen = "true";
	
	public ExecutionLogger(Context context, Properties props) {
		isLoggingEnabled = PropertyHandler.getValue(props, PropertyHandler.CFG_LOGGING_ENABLED).toLowerCase();
		isLogToScreen = PropertyHandler.getValue(props, PropertyHandler.CFG_LOG_TO_SCREEN).toLowerCase();
		if(isLogToScreen == "false") {
			logger = context.getLogger();
		}
	}
	
	public void log(String msg) {
		if(isLoggingEnabled.equals("true")) {
			if(isLogToScreen.equals("true")) {
				System.out.println(msg);
			}else {
				logger.log( msg);
			}
		}
	}
	
	public void log(String msg, Exception ex) {
		if(isLoggingEnabled.equals("true")) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			ex.printStackTrace(pw);
			if(isLogToScreen.equals("true")) {
				System.out.println(sw.toString());
			}else {
				logger.log(msg + " : "+ sw.toString());
			}
			
		}
	}
	
	
}
