# AWS Lambda SAP OAuth Token Generator

This project contains a sample Lambda code in Java to generate OAuth tokens from a backend SAP ABAP system using OpenSAML2 library. The Lambda function generates a SAML message with Amazon Cognito user ID as the SAML NameID and submits it to the backend SAP ABAP system's OAuth token endpoint to generate an OAuth token.

# Getting Started

### Prerequisites
- SAP ABAP system version 7.x with [SAP Gateway](https://www.sap.com/community/topic/gateway.html "SAP Gateway") configured and operational. If you don't have an ABAP system, you can download and install the SAP ABAP Developer Edition from [here](https://store.sap.com/sap/cpa/ui/resources/store/html/SolutionDetails.html?pid=0000014493&catID=&pcntry=DE&sap-language=EN&_cp_id=id-1477346420741-0.  "here") or use the [SAP Cloud Appliance Library](https://cal.sap.com/ "SAP Cloud Appliance Library")
- Basic understanding of how SAML and OAuth work in SAP ABAP application. Check [here](https://wiki.scn.sap.com/wiki/display/Security/Using+OAuth+2.0+from+a+Web+Application+with+SAML+Bearer+Assertion+Flow#UsingOAuth2.0fromaWebApplicationwithSAMLBearerAssertionFlow-ConfigurationGuideforthisscenario "here") for more information.
- Basic understanding of how AWS Lambda and Amazon API Gateway works
- Administrator access in the SAP ABAP System
- Non-production(Sandbox) SAP ABAP system is highly recommended
- The SAP ABAP system is reachable by your AWS account services (for e.g. API Gateway) on the HTTPs port of the ABAP system.
- It is recommended that you front the ABAP System using an Application or Network Load Balancer.


### Installing

1. Clone this repository into a folder of choice
1. Build the project using one of the options provided [here](https://docs.aws.amazon.com/lambda/latest/dg/lambda-java-how-to-create-deployment-package.html "here"). I recommend build using [Eclipse plugin.](https://docs.aws.amazon.com/lambda/latest/dg/java-create-jar-pkg-maven-and-eclipse.html "Eclipse plugin."). Also, you only need to build the project. So, for e.g., you will only perform step 4 & 5 if you use Eclipse to build the project
1. Build process will create a 'lambda-sap-oauth-0.0.1-SNAPSHOT.jar' file in the 'target' sub-folder
1. Create a lambda function (for e.g. sap-oauth-token-generator) using the 'lambda-sap-oauth-0.0.1-SNAPSHOT.jar' created above
1. Create an Amazon Cognito User Pool and an user ID within that pool. Check [here](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html "here") for more info.
1. Create an API Gateway API with a 'Post' method attached to the root resource and Lambda Proxy Integration using the lambda function created above.
1. Use the congnito user pool as 'Authorization ' under settings for the 'Post' method
1. Deploy the API.
1. You will need the metadata XML file to setup trust between AWS Lambda and backend SAP ABAP system. To generate this metadata XML, you will have to first create a private and public key by running the following commands from terminal

	`$> openssl req -newkey rsa:2048 -nodes -keyout tmpkey.pem -x509 -days 365 -out certificate.pem`

	`$>openssl pkcs8 -topk8 -inform PEM -outform PEM -in tmpkey.pem -out key.pem -nocrypt`
1. This will create two files, certificate.pem and key.pem. Upload these files to a S3 bucket in the same acount/region where you created the lambda function above
1. To setup SAML/OAuth in SAP, you will need a metadata XML file. You can generate it by calling the API (POST method) you created above with the following JSON payload.

	```json
	{
		"action" : "metadata",
		"aws_logging_enabled" : "true",
		"aws_logs_to_screen" : "true",
		"aws_bucket" : "<S3 bucket where you stored the key.pem and cert.pem files>",
		"aws_key_file" : "<S3 file key where you stored the key.pem file. For e.g., aws-sap-saml-keys/key.pem> ",
		"aws_cert_file" : "<S3 file key where you stored the cert.pem file. For e.g., aws-sap-saml-keys/key.pem> ",
		"aws_nlb_host":"<Host name of the NLB or ALB that you used to front the SAP system for e.g. sapapigwABAPNLB-xxxxxxxx.elb.us-east-1.amazonaws.com >",
		"aws_nlb_url":"<Url to call for the NLB. For e.g. https://sapapigwABAPNLB-xxxxxxxx.elb.us-east-1.amazonaws.com/sap/bc/sec/oauth2/token>",
		"aws_sap_token_scope": "<OAuth token scope in SAP. For e.g. ZGWSAMPLE_BASIC_0001>",
		"saml_issuer":"AWSLambda",
		"saml_nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"oa2_endpoint_host": "<OAuth token end point host of the backend SAP system for e.g. vhcalnplci.dummy.nodomain:44300>",
		"oa2_token_endpoint" : "<OAuth token end point of the backend SAP system for e.g. https://vhcalnplci.dummy.nodomain:44300/sap/bc/sec/oauth2/token>",
		"scope" : "<OAuth token scope in SAP. For e.g. ZGWSAMPLE_BASIC_0001>",
		"saml_session_authentication": "urn:none",
		"saml_audience_restriction":"<SAML Audience for the backend SAP system for e.g. NPL_001",
		"oa2_client_id":"<System User ID in SAP system that is created for OAuth Client ID>"
		"oa2_client_password":"<Password for the OAuth Client ID>"
	}
```
Note: For oa2_token_endpoint and oa2_endpoint_host, make sure you use the correct port number. If you are using NLB, then all requests are proxied through, so you will use the port number of the backend SAP system (for e.g. 44300). If you are using an ALB, then the port where ALB listens to HTTPs request should be used instead of the port of the backend SAP system. This is because, the SAP system makes a URL check between the receipient information in SAML with the port from where the request came in from.

1. Once the SAML/OAuth configuration in backend SAP system is setup, you can get the access token using the same payload as above except the field action which should have a value of 'accessToken'.

## Additional Resources
- [Constrained Authorization and Single Sign-On for OData services in SAP](https://wiki.scn.sap.com/wiki/display/Security/OAuth+2.0+-+Constrained+Authorization+and+Single+Sign-On+for+OData+Services "Constrained Authorization and Single Sign-On for OData services in SAP")
- [Troubleshooting SAML2.0 scenarios in SAP](https://wiki.scn.sap.com/wiki/display/Security/Troubleshooting+SAML+2.0+Scenarios "Troubleshooting SAML2.0 scenarios in SAP")
- [Using OAuth 2.0 with SAML Bearer Assertion Flow](https://wiki.scn.sap.com/wiki/display/Security/Using+OAuth+2.0+from+a+Web+Application+with+SAML+Bearer+Assertion+Flow "Using OAuth 2.0 with SAML Bearer Assertion Flow")


## License

See the [LICENSE](LICENSE) file for details. See the [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) file for details about 3rd party software and their licenses.
