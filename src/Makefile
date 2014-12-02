PARAMS = mykeystore ahamad mykey

all :
	@javac SDDRClient.java SDDRServer.java SDDRDataReader.java SDDRDataWriter.java

client : all
	@java -Djavax.net.ssl.keyStore=mykeystore -Djavax.net.ssl.keyStorePassword=ahamad -Djavax.net.ssl.trustStore=mykeystore -Djavax.net.ssl.trustStorePassword=ahamad SDDRClient $(PARAMS)

server : all
	@java -Djavax.net.ssl.keyStore=mykeystore -Djavax.net.ssl.keyStorePassword=ahamad -Djavax.net.ssl.trustStore=mykeystore -Djavax.net.ssl.trustStorePassword=ahamad SDDRServer $(PARAMS)

clean :
	@rm -rf *.class
