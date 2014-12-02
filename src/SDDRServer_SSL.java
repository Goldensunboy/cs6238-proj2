import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.attribute.AclFileAttributeView;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.acl.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * Secure Distributed Data Repository Server
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRServer_SSL extends Thread {
	
	private static final boolean DEBUG = true;
	private static final String DOES_NOT_EXIST = "does_not_exist";
	
	/** Port that SDDR server always binds to */
	private static final int SDDR_PORT = 40231;
	
	//AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class);
	
	//Class to store values for a particular file
	private class FileValues {
		private byte[] aesEncKey = null;
		private String secflag = null;
		private byte[] realSign = null;
		
		public FileValues(byte[] aesEncKey,String secflag,byte[] realSign) {
			this.aesEncKey = aesEncKey;
			this.secflag = secflag;
			this.realSign = realSign;
		}
	}
	
	//HashMap used to provide access to file metadata using filename as the key
	private static HashMap<String, FileValues> hashMap = new HashMap<String, FileValues>();
		
	
	/**
	 * put(Document UID, SecurityFlag): A document is sent to the server over the secure channel that was 
	 * established when the session was initiated. If the document already exists on the server, you may 
	 * overwrite it along with its meta-data. If a new document is put, this client becomes the owner of the 
	 * document. If the client is able to update because of a delegation, the owner does not change. You need to 
	 * use some scheme to ensure that documents created by different clients have unique UIDs. The 
	 * SecurityFlag specifies how document data should be stored on the server
	 */
	private void put(PublicKey pubKey, PrivateKey privKey) {
		System.out.println("Received command from " + clientname + ": put");
		
		try {
			// receive the file name
			String filename = in.readLine();
			System.out.println("Filename is " + filename);
			// creating the file on server
			File file = new File(filename); // renaming the file while put...just for visibility
			if (file.exists()) {
				System.out.println("File " + filename + " already exists...OVERWRITING \n ");
			}
			 
			//Receiving the security flag
			String secflag = in.readLine();
			System.out.println("SecFlag received is " + secflag);
			
			//receiving the filesize
			String reply = in.readLine();
			int filesize = Integer.parseInt(reply);
			System.out.println("File Size received is " + filesize);
			byte filebytes[] = new byte[filesize];
			int bytesread = 0;
			
			//reading the file sent from client
			while(bytesread < filesize) {
				int thisread = din.read(filebytes, bytesread, filesize - bytesread);
				if(thisread >= 0) {
					bytesread += thisread;
				} else {
					System.out.println("Encountered an error while downloading file");
				}
			}
			
			FileOutputStream fos = new FileOutputStream(file);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			//FileValues filevalues = null;
			
			if (secflag.equals("CONFIDENTIAL")) {
				System.out.println("Document Encryption required");
				
				//Generating random AES key
				KeyGenerator keygen = KeyGenerator.getInstance("AES");
				keygen.init(128);
				byte[] aesKeyBytes = keygen.generateKey().getEncoded();
				
				//Encrypting file contents using above generate key
				SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes,"AES");
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			    byte[] cipherText = new byte[cipher.getOutputSize(filesize)];
			    int ctLength = cipher.update(filebytes, 0, filesize, cipherText, 0); // filebytes contain the data of file in byte[] format
			    ctLength += cipher.doFinal(cipherText, ctLength);
			    System.out.println(new String(cipherText));
			    System.out.println(ctLength);
			    
			    //Writing encrypted file
				bos.write(cipherText, 0, ctLength);
				bos.flush();
				
				//Encrypting AES key with Server's Public key
				Cipher pkCipher = Cipher.getInstance("RSA");
				pkCipher.init(Cipher.ENCRYPT_MODE, pubKey);
				byte[] aesEncKey = pkCipher.doFinal(aesKeyBytes);
				byte[] realSign = {0x00,0x00,0x00,0x00}; // Just initializing the value
				// writing file contents into the hashmap declared - serialization to be done
				FileValues filevalues = new FileValues(aesEncKey,secflag,realSign);
				hashMap.put(filename, filevalues);
				
				
			    //Decryption pass to be used later
			    cipher.init(Cipher.DECRYPT_MODE, aesKey);
			    byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
			    int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
			    ptLength += cipher.doFinal(plainText, ptLength);
			    System.out.println(new String(plainText));
			    System.out.println(ptLength);
			    
				
				
			} else if (secflag.equals("INTEGRITY")) {
				System.out.println("Document Signing required");
				
				//Signing the document using private key of server
				Signature dsa = Signature.getInstance("SHA1withRSA");
				dsa.initSign(privKey);
				dsa.update(filebytes); // filebytes contain the data of file in byte[] format
				byte[] realSign = dsa.sign();
				System.out.println("Signature of the document received is " + realSign.toString());
				
				// Writing the file related values into hashmap
				byte[] aesEncKey = {0x00,0x00,0x00,0x00}; // Just initializing the value
				FileValues filevalues = new FileValues(aesEncKey,secflag,realSign);
				hashMap.put(filename, filevalues);
				
				//Writing plain file
				bos.write(filebytes, 0, filesize);
				bos.flush();
				
			} else if (secflag.equals("NONE")) {
				System.out.println("you are good..no manipulation required");
				
				byte[] aesEncKey = {0x00,0x00,0x00,0x00}; // Just initializing the value
				byte[] realSign = {0x00,0x00,0x00,0x00};
				FileValues filevalues = new FileValues(aesEncKey,secflag,realSign);
				hashMap.put(filename, filevalues);
				
				//Writing plain file
				bos.write(filebytes, 0, filesize);
				bos.flush();
			}
			
			
			// Write the file on server
//			FileOutputStream fos = new FileOutputStream(file);
//			BufferedOutputStream bos = new BufferedOutputStream(fos);
//			bos.write(filebytes, 0, filesize);
//			bos.flush();
			bos.close();
			fos.close();

			System.out.println("File successfully received "+ filename + "\n");
			
			//Maitaining File attributes - may help with delegation
			
		} catch(Exception e) {
			System.out.println("Exception while putting file");
			e.printStackTrace();
		}
		//TODO
	}
	
	/**
	 * get(Document UID): After a session is established, a client can request a document over the secure 
	 * channel from the server using this call. A request coming over a session is honored only if it is for a 
	 * document owned by the client that set up the session, or this client has a valid delegation (see delegate 
	 * call). If successful, a local copy of the document data is made available to the client. The server must 
	 * maintain information about documents (e.g., meta-data) that allows it to locate the requested document, 
	 * decrypt it and send the data to the requestor
	 */
	private void get(PublicKey pubKey,PrivateKey privKey) {
		System.out.print("Received command from " + clientname + ": get ");
		
		try {
			// Receive the file name
			String filename = in.readLine();
			System.out.println(filename);
			
			// If this file doesn't exist, return an error message
			File f = new File(filename);
			if(!f.exists()) {
				System.out.println("File " + filename + " does not exist.");
				out.write(DOES_NOT_EXIST + '\n');
				out.flush();
				return;
			}
			
			// Get the file information, send length to user
			int filesize = (int) f.length();
//			out.write(filesize + "\n");
//			out.flush();
			
			//Decrypting encrypted AES key with Server's Private Key
//			byte[] aesEncKey = null;
//			Cipher skCipher = Cipher.getInstance("RSA");
//			skCipher.init(Cipher.DECRYPT_MODE, privKey);
//			skCipher.doFinal(aesEncKey);
			
			// Reading the file from server into filebytes
			byte filebytes[] = new byte[filesize];
			FileInputStream fis = new FileInputStream(f);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(filebytes, 0, filesize);
			bis.close();
			fis.close();
			
			
			//Retrieving values from HashMap
			FileValues filevalues = hashMap.get(filename);
			
			if (filevalues.secflag.equals("CONFIDENTIAL")) {
				//Encrypted file present - Decrypt and then send
				System.out.println("Sending encrypted file in plaintext to client");
				//Decrypting AES-encrypted key using Server's private key
				Cipher skCipher = Cipher.getInstance("RSA");
				skCipher.init(Cipher.DECRYPT_MODE, privKey);
				byte[] aesKey = skCipher.doFinal(filevalues.aesEncKey);
				
				//Decrypting the filebytes contents using above decrypted AES key
				SecretKeySpec keySpec = new SecretKeySpec(aesKey,"AES");
				Cipher sCipher = Cipher.getInstance("AES");
			    sCipher.init(Cipher.DECRYPT_MODE, keySpec);
			    byte[] plainText = new byte[sCipher.getOutputSize(filesize)];
			    int ptLength = sCipher.update(filebytes, 0, filesize, plainText, 0);
			    ptLength += sCipher.doFinal(plainText, ptLength);
			    System.out.println("Decrypted contents before sending are");
			    System.out.println(new String(plainText));
			    System.out.println(ptLength);
			    
			    //Sending decrypted file length to the client to enable it reading
			    out.write(ptLength + "\n");
			    out.flush();
			    
			    //Sending decrypted file contents to client
			    dout.write(plainText, 0, ptLength);
			    dout.flush();
			    
				
			} else if (filevalues.secflag.equals("INTEGRITY")) {
				//Signed file present
				System.out.println("Sending plain file after checking its integrity");
				//Verifying signature of the file before sending
				Signature sign = Signature.getInstance("SHA1withRSA");
				sign.initVerify(pubKey);
				sign.update(filebytes, 0, filesize);
				boolean verifies = sign.verify(filevalues.realSign);
				if (!verifies) {
					System.out.println("Calculated signature does not match with saved sign");
					out.write("SIGNATURE_MISMATCH" + "\n");
					out.flush();
					return;
				}
				
				//Sending file length to client
				out.write(filesize + "\n");
				out.flush();
				//Sending the file to cient
				dout.write(filebytes, 0, filesize);
				dout.flush();
			} else if (filevalues.secflag.equals("NONE")) {
				//Plain file present
				System.out.println("Sending plain text file to client");
				//Sending file length to client
				out.write(filesize + "\n");
				out.flush();
				//Sending the file to cient
				dout.write(filebytes, 0, filesize);
				dout.flush();
			}
			
 
//			//Sending the file to cient
//			dout.write(filebytes, 0, filesize);
//			dout.flush();

			
			System.out.println("Successfully sent " + filename);
			
		} catch (Exception e) {
			System.out.println("Exception while getting file");
			e.printStackTrace();
		}
	}
	
	/**
	 * delegate(Document UID, client C, time T, PropagationFlag): A delegation credential (e.g., signed 
	 * token) is generated that allows an owner client to delegate rights (put, get or both) for a document to 
	 * another client C for a time duration of T. If C is ALL, the delegation is made to any client in the system 
	 * for this document. If you use a protocol that needs to securely exchange messages between clients for 
	 * implementing delegation, you should use secure channels. PropagationFlag is a Boolean that specifies if 
	 * C can propagate the rights delegated to it. A true value permits delegation and false disallows it
	 */
	private void delegate() {
		System.out.println("Received command from " + clientname + ": delegate");
		//TODO
	}
	
	/**
	 * Main server method to run after arguments are validated.
	 * Bind to a port for initiating secure sessions with clients.
	 */
	private Socket socket = null;
	private String clientname = null;
	private BufferedReader in = null;
	private PrintWriter out = null;
	private DataOutputStream dout = null;
	private DataInputStream din = null;
	
	private String keyfile = null;
	private String keypass = null;
	
	public void run() {
		System.out.println("Connected to user " + clientname + ":" + socket.getPort() + "!");
		
		// Fields used to handle the client connection
		boolean finished = false;
		
		try {
			// Get input and output handles for client communication
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream());
			dout = new DataOutputStream(socket.getOutputStream());
			din = new DataInputStream(socket.getInputStream());
			
			File file = new File(keyfile);
			FileInputStream fis = new FileInputStream(file);
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(fis,keypass.toCharArray());

			//Receiving alias from Client
			String alias = in.readLine();
			Boolean valid = keystore.containsAlias(alias);	
			System.out.println("prabs " + valid);
			if (!valid) {
				System.out.println(alias + " not found in trusted store \n Try with another alias");
				out.write("cancel\n");
				out.flush();
				finished = true;
			} else {
				out.write("connect\n");
				out.flush();
			}
			
			//Extracting server's public and private key from trusted store for alias "mykey"
			// Alias is assumed to be hardcoded as "mykey" for server

			//keystore.getCertificate("mykey");
			
			PrivateKey privKey = (PrivateKey) keystore.getKey("mykey",keypass.toCharArray());
			PublicKey pubKey = keystore.getCertificate("mykey").getPublicKey(); 
				
			// Receive commands from client until user ends the session
			do {
				String command = in.readLine();
//				if(DEBUG) System.out.println("\tCommand: " + command);
				switch(command) {
				case "end-ssession":
					finished = true;
					break;
				case "put":
					put(pubKey, privKey);
					break;
				case "get":
					get(pubKey,privKey);
					break;
				case "delegate":
					delegate();
					break;
				default:
					System.out.println("Unknown command received: " + command);
				}
			} while(!finished);
			in.close();
			out.close();
		} catch(Exception e) {
			System.out.println("Connection to user " + clientname + " interrupted: " + e.getMessage());
			e.printStackTrace();
		} 
		
		System.out.println("Ended connection with user " + socket.getInetAddress().toString().substring(1) +
				":" + socket.getPort() + ".");
	}
	
	/**
	 * Create a new SDDR Server
	 * @param Socket The socket to communicate with the client
	 */
	public SDDRServer_SSL(SSLSocket Socket, String keyfile, String keypass) {
		this.socket = Socket;
		clientname = Socket.getInetAddress().toString().substring(1);
		this.keyfile = keyfile;
		this.keypass = keypass;
	}
	
	/**
	 * Terminate the SDDR server with an error message
	 * @param message What went wrong
	 */
	private static void sddrserver_fail(String message) {
		System.out.println(message);
		System.exit(1);
	}
	
	/**
	 * Validate the argument, and bind to a port to listen for incoming connections
	 * @param args The port to bind this server to
	 */
	public static void main(String[] args) {
		if(args.length < 2) {
			sddrserver_fail("Program usage: java SDDRServer_SSL keystore keystorepass");
		}
		
		//Setting SSL system properties
		System.setProperty("javax.net.ssl.keyStore", args[0]);
		System.setProperty("javax.net.ssl.keyStorePassword", args[1]);
		System.setProperty("javax.net.ssl.trustStore", args[0]);
		System.setProperty("javax.net.ssl.trustStorePassword", args[1]);
		
		
		
		SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket ss = null;
		try {
			ss = (SSLServerSocket) ssf.createServerSocket(SDDR_PORT);
			ss.setNeedClientAuth(true);
			System.out.println("Listening for incoming connections on port " + SDDR_PORT + "...");
			
			while(true) {
				// also passing keystore filename and password to run()
				new SDDRServer_SSL((SSLSocket) ss.accept(),args[0],args[1]).start(); 
			}
		} catch(Exception e) {
                        System.out.println("prabs is here");
                        e.printStackTrace();
			sddrserver_fail("Server encountered an error: " + e.getMessage());
		}
	}
}
