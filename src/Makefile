all :
	@javac SDDRClient.java SDDRServer.java

client : all
	@java -Djavax.net.ssl.keyStore=mykeystore -Djavax.net.ssl.keyStorePassword=ahamad -Djavax.net.ssl.trustStore=mykeystore -Djavax.net.ssl.trustStorePassword=ahamad SDDRClient

server : all
	@java -Djavax.net.ssl.keyStore=mykeystore -Djavax.net.ssl.keyStorePassword=ahamad -Djavax.net.ssl.trustStore=mykeystore -Djavax.net.ssl.trustStorePassword=ahamad SDDRServer


