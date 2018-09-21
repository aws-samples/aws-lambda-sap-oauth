package com.aws.sap.sample.lambda.sap.oauth;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Properties;
import javax.xml.transform.*;  
import java.io.StringWriter;
import java.io.StringReader;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import com.amazonaws.services.lambda.runtime.Context; 
import static org.mockito.Mockito.*;

public class TestLocalSamlTokenFactory {

  Context context = mock(Context.class);
  static private ExecutionLogger _logger;
  Properties configProps = new Properties();

  @Test
  public void TestLocalSamlToken() throws Exception {
    configProps.setProperty(PropertyHandler.CFG_LOGGING_ENABLED, "true");
    configProps.setProperty(PropertyHandler.CFG_LOG_TO_SCREEN, "true");
    _logger = new ExecutionLogger(context, configProps);
    configProps.setProperty("saml_nameid", "foo");
    configProps.setProperty(PropertyHandler.CFG_OA2_TOKEN_ENDPOINT, "https://vhcalnplci.dummy.nodomain:44300/sap/bc/sec/oauth2/token");
    configProps.setProperty(PropertyHandler.CFG_SAML_AUDIENCE_RESTRICTION, "NPL_001");
    configProps.setProperty(PropertyHandler.CFG_SAML_ISSUER, "AWSLambda");
    configProps.setProperty(PropertyHandler.CFG_OA2_CLIENT_ID, "abc123");
    configProps.setProperty(PropertyHandler.CFG_AWS_BUCKET, "pmotyko-aws-lambda-sap-oauth");
    configProps.setProperty(PropertyHandler.CFG_AWS_KEY_FILE, "key.pem");
    configProps.setProperty(PropertyHandler.CFG_AWS_CERT_FILE, "certificate.pem");
    LocalSamlTokenFactory localSamlTokenFactory = (LocalSamlTokenFactory) LocalSamlTokenFactory.getInstance(configProps, _logger);
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
    StreamResult result = new StreamResult(new StringWriter());
    StreamSource source = new StreamSource(new StringReader(localSamlTokenFactory.getSamlAssertion(configProps)));
    transformer.transform(source, result);
    _logger.log(result.getWriter().toString());
  }
}