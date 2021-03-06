import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.net.SocketFactory;

/**
 * Secure Distributed Data Repository Client
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRClient {
	
	private static final String DOES_NOT_EXIST = "does_not_exist";
	
	/** Options allowed for function flags */
	private static final String[] SECURITY_FLAG_OPTIONS = {
		"CONFIDENTIAL",
		"INTEGRITY",
		"NONE"
	};
	private static final String[] PROPAGATION_FLAG_OPTIONS = {
		"true",
		"false"
	};
	
	/** Port that SDDR server always binds to */
	private static final int SDDR_PORT = 40231;
	
	/**
	 * start-ssession(hostname): A new secure session is started with the server running at host hostname. 
	 * Mutual authentication is performed, and a secure communication channel is established between the client 
	 * executing this call and the server.
	 */
	private static void start_ssession(String hostname) {
		System.out.println("Connecting to " + hostname + ":" + SDDR_PORT + "...");
		
		// Connect to the server
		SocketFactory socketFactory = SocketFactory.getDefault();
	    try {
	    	// Initiate unencrypted connection
			socket = socketFactory.createSocket(hostname, SDDR_PORT);
			in = new DataInputStream(socket.getInputStream());
		    out = new DataOutputStream(socket.getOutputStream());
		    ObjectOutputStream objout = new ObjectOutputStream(socket.getOutputStream());
		    ObjectInputStream objin = new ObjectInputStream(socket.getInputStream());
		    
		    // Step 1: Client sends its alias to server
		    objout.writeObject(user_alias);
		    
		    // Step 2: Receive server alias
		    String server_alias = (String) objin.readObject();
		    Certificate cert = keystore.getCertificate(server_alias);
			PublicKey server_key = cert.getPublicKey();
		    
		    // Step 3: Send Pub_S[K] to server
		    int K = new Random().nextInt();
		    byte[] K_bytes = ByteBuffer.allocate(4).putInt(K).array();
		    Cipher c = Cipher.getInstance("RSA");
		    c.init(Cipher.ENCRYPT_MODE, server_key);
		    byte[] K_encrypted = c.doFinal(K_bytes);
		    out.writeInt(K_encrypted.length);
		    out.write(K_encrypted);
		    
		    // Step 4: Receive Pub_C[X] from server
		    int X_len = in.readInt();
		    byte[] X_encrypted = new byte[X_len];
		    int bytes_received = 0;
		    while(bytes_received < X_len) {
		    	int this_read = in.read(X_encrypted, bytes_received, X_len - bytes_received);
		    	if(this_read == -1) {
		    		throw new Exception("Connection error");
		    	} else {
		    		bytes_received += this_read;
		    	}
		    }
		    
		    // Step 5: Send Pub_S[X+1] to server
		    c.init(Cipher.DECRYPT_MODE, privkey);
		    byte[] X_bytes = c.doFinal(X_encrypted);
		    int X = ByteBuffer.wrap(X_bytes).getInt();
		    X++;
		    byte[] Xplusone_bytes = ByteBuffer.allocate(4).putInt(X).array();
		    c.init(Cipher.ENCRYPT_MODE, server_key);
		    byte[] Xplusone_encrypted = c.doFinal(Xplusone_bytes);
		    out.writeInt(Xplusone_encrypted.length);
		    out.write(Xplusone_encrypted);
		    
		    // Step 6: Receive Pub_C[K+1] from server
		    int Kplusone_len = in.readInt();
		    byte[] Kplusone_encrypted = new byte[Kplusone_len];
		    bytes_received = 0;
		    while(bytes_received < Kplusone_len) {
		    	int this_read = in.read(Kplusone_encrypted, bytes_received, Kplusone_len - bytes_received);
		    	if(this_read == -1) {
		    		throw new Exception("Connection error");
		    	} else {
		    		bytes_received += this_read;
		    	}
		    }
		    c.init(Cipher.DECRYPT_MODE, privkey);
		    byte[] Kplusone_bytes = c.doFinal(Kplusone_encrypted);
		    int Kplusone = ByteBuffer.wrap(Kplusone_bytes).getInt();
		    
		    // Step 7: Send ACK/NACK
		    String msg = K + 1 == Kplusone ? "SUCCESS" : "FAILURE";
		    objout.writeObject(msg);
		    
		    // Step 8: Receive ACK/NACK
		    msg = (String) objin.readObject();
		    switch(msg) {
		    case "FAILURE":
		    	throw new Exception("Server failed to validate client");
		    case "CLIENT_FAILURE":
		    	throw new Exception("Client failed to validate server");
		    default:
		    }
		    
		    // Step 9: Generate session key, send it to server
		    KeyGenerator aeskeygen = KeyGenerator.getInstance("AES");
			aeskeygen.init(128, new SecureRandom());
			byte[] shared_key = aeskeygen.generateKey().getEncoded();
			c.init(Cipher.ENCRYPT_MODE, server_key);
			byte[] shared_key_encrypted = c.doFinal(shared_key);
			out.writeInt(shared_key_encrypted.length);
			out.write(shared_key_encrypted);
			
		    // Generate secure reader and writer
			sddr_in = new SDDRDataReader(socket.getInputStream(), shared_key);
			sddr_out = new SDDRDataWriter(socket.getOutputStream(), shared_key);
			
	    } catch (UnknownHostException e) {
			System.out.println("Unknown host: " + hostname);
			return;
	    } catch (ConnectException e) {
	    	System.out.println("Server not running on host: " + hostname);
	    	return;
	    } catch (EOFException e) {
	    	System.out.println("Server encountered an error in authentication");
	    	return;
		} catch (Exception e) {
			System.out.println("Failed to initiate connection: " + e.getMessage());
			e.printStackTrace();
			try {
				if(socket != null) {
					socket.close();
					socket = null;
				}
				if(in != null) {
					in.close();
					in = null;
				}
				if(out != null) {
					out.close();
					out = null;
				}
				if(sddr_in != null) {
					sddr_in.close();
					sddr_in = null;
				}
				if(sddr_out != null) {
					sddr_out.close();
					sddr_out = null;
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			return;
		}
	    
	    // Successfully initiated a connection
	 	SDDRClient.hostname = hostname;
	    System.out.println("Successfully connected to server!");
	}
	
	/**
	 * end-ssession(): Terminates the current session. If any documents that were received from the server are 
	 * updated, their new copies must be sent to the server before session termination completes
	 */
	private static void end_ssession() {
		System.out.println("Terminating connection with " + hostname + "...");
		
		// Send command to server
		sddr_out.writeString("end-ssession");
		
		// Attempt to close the communication socket
		try {
			socket.close();
			in.close();
			out.close();
			sddr_in.close();
			sddr_out.close();
		} catch (SocketException e) {
			System.out.println("Server connection interrupted prematurely: " + e.getMessage());
		} catch (Exception e) {
			System.out.println("Error closing connection: " + e.getMessage());
		}
		
		// Set fields to null since they are invalidated now
		hostname = null;
		socket = null;
		in = null;
		out = null;
		sddr_in = null;
		sddr_out = null;
	}
	
	/**
	 * put(Document UID, SecurityFlag): A document is sent to the server over the secure channel that was 
	 * established when the session was initiated. If the document already exists on the server, you may 
	 * overwrite it along with its meta-data. If a new document is put, this client becomes the owner of the 
	 * document. If the client is able to update because of a delegation, the owner does not change. You need to 
	 * use some scheme to ensure that documents created by different clients have unique UIDs. The 
	 * SecurityFlag specifies how document data should be stored on the server
	 */
	private static void put(String document, String secflag) {
		System.out.println("Sending " + document + " with flag " + secflag + " to " + hostname + "...");
		
		try {
			// Send command to server
			sddr_out.writeString("put");
			
			// Send filename to the server
			sddr_out.writeString(document);
			
			// Send security flag to the server
			sddr_out.writeString(secflag);
			
			// Can we write this file?
			if("FAILURE".equals(sddr_in.readString())) {
				System.out.println("You do not have permission to write file: " + document);
				return;
			}
			
			// Read file into byte array
			File file = new File(document);
			int filesize = (int) file.length();
			byte filebytes[] = new byte[filesize];
			FileInputStream fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(filebytes, 0, filesize);
			bis.close();
			fis.close();
			sddr_out.writeData(filebytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * get(Document UID): After a session is established, a client can request a document over the secure 
	 * channel from the server using this call. A request coming over a session is honored only if it is for a 
	 * document owned by the client that set up the session, or this client has a valid delegation (see delegate 
	 * call). If successful, a local copy of the document data is made available to the client. The server must 
	 * maintain information about documents (e.g., meta-data) that allows it to locate the requested document, 
	 * decrypt it and send the data to the requestor
	 */
	private static void get(String document) {
		System.out.println("Getting " + document + " from " + hostname + "...");
		
		try {
			// Send command to server
			sddr_out.writeString("get");
			
			// Send file name to server
			sddr_out.writeString(document);
			
			// Does the file exist?
			String reply = sddr_in.readString();
			if(DOES_NOT_EXIST.equals(reply)) {
				System.out.println("File \"" + document + "\" does not exist.");
				return;
			}
			
			// Can we get this file?
			reply = sddr_in.readString();
			if("FAILURE".equals(reply)) {
				System.out.println("You do not have permission to get file: " + document);
				return;
			}
			
			// Get the status of the file integrity
			if("TAMPERED".equals(sddr_in.readString())) {
				System.out.println("Warning: Integrity check of the file failed!");
			}
			
			// Get the file
			byte[] filebytes = sddr_in.readData();
			
			// Write the file
			File f = new File(document);
			if(f.exists()) {
				f.delete();
			}
			FileOutputStream fos = new FileOutputStream(f);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			bos.write(filebytes, 0, filebytes.length);
			bos.flush();
			bos.close();
			fos.close();
			
		} catch (Exception e) {
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
	private static void delegate(String document, String client, int time, boolean propagation_flag, String delegationType) {
		System.out.println("Delegating " + document + " to " + client + " with flag " + propagation_flag +
				" for " + time + " seconds...");
		
		// Send command to server
		sddr_out.writeString("delegate");
		
		// Send document name to server
		sddr_out.writeString(document);
		
		// Send client name to server
		sddr_out.writeString(client);
		
		// Send delegation length to server
		sddr_out.writeString("" + time);
		
		// Send propagation flag to server
		sddr_out.writeString("" + propagation_flag);
		
		// Send delegation type to server
		sddr_out.writeString(delegationType);
		
		// Was the delegation successful?
		if("FAILURE".equals(sddr_in.readString())) {
			System.out.println("Failed to delegate rights to " + document + " for user: " + client);
		} else {
			System.out.println("Successfully delegated rights to " + document + " for user: " + client);
		}
	}
	
	/**
	 * Display a message about this program's usage
	 */
	private static void display_help() {
		System.out.println("Command usage:\n" +
				"\t(h)elp                      Display this message\n" +
				"\te(x)it                      Terminate the SDDR client\n" +
				"\t(s)tart-ssession <hostname> Initiate secure session with hostname\n" +
				"\t(e)nd-ssession              Terminate current secure session\n" +
				"\t(g)et <document>            Download document from the server\n" +
				"\t(p)ut <document> <secflag>  Upload document with security parameters:\n" +
				"\t\tsecflag: CONFIDENTIAL : The file will be encrypted server-side\n" +
				"\t\t         INTEGRITY    : Document integrity is validated before downloading\n" +
				"\t\t         NONE         : Neither encryption nor signing will take place\n" +
				"\t(d)elegate <document> <client> <time> <propflag> <type>\n" +
				"\t\tAllows delegation of document to client for time seconds.\n" +
				"\t\tIf client is ALL, delegate to everyone.\n" +
				"\t\tpropflag: true  : Users may propagate delegation rights of file via delegate command\n" +
				"\t\t          false : Users may not propagate delegation rights" +
				"\t\ttype: put  : Users can put a file" +
				"\t\t      get  : Users can get a file" +
				"\t\t      both : Users may put pr get a file");
	}
	
	/**
	 * SDDR client main.
	 * While the user hasn't exited, allow connection to SDDR servers.
	 * During connection, allow upload, download and delegation of files.
	 * @param args Unused
	 */
	private static String hostname = null;
	private static Socket socket = null;
	private static DataInputStream in = null;
	private static DataOutputStream out = null;
	private static SDDRDataReader sddr_in = null;
	private static SDDRDataWriter sddr_out = null;
	private static PublicKey pubkey = null;
	private static PrivateKey privkey = null;
	private static String user_alias = null;
	private static KeyStore keystore = null;
	public static void main(String[] args) throws KeyStoreException,
	                                              NoSuchProviderException,
	                                              NoSuchAlgorithmException,
	                                              CertificateException,
	                                              IOException,
	                                              UnrecoverableKeyException {
		
		// Get client keys and certificate
		FileInputStream keyStoreFileStream = new FileInputStream(args[0]);
		keystore = KeyStore.getInstance("JKS");
		keystore.load(keyStoreFileStream, args[1].toCharArray());
		Certificate cert = keystore.getCertificate(args[2]);
		pubkey = cert.getPublicKey();
		privkey = (PrivateKey) keystore.getKey(args[2], args[1].toCharArray());
		user_alias = args[2];
		
		// Fields used by the client to communicate with the server
		Scanner user_input = new Scanner(System.in);
		Collection<String> security_flag_options = new ArrayList<String>();
		Collection<String> propagation_flag_options = new ArrayList<String>();
		for(String s : SECURITY_FLAG_OPTIONS) {
			security_flag_options.add(s);
		}
		for(String s : PROPAGATION_FLAG_OPTIONS) {
			propagation_flag_options.add(s);
		}
		boolean finished = false;
		
		// Welcome message
		System.out.println("Welcome to the Secure Distributed Data Repository client!");
		System.out.println("Type \"help\" for a list of commands and their usage.");
		
		// Allow multiple connects and disconnects with the server
		do {
			System.out.print("> ");
			String command = user_input.nextLine();
			String[] params = command.split(" ");
			
			// Switch on the command issued
			switch(params[0]) {
			case "help":
			case "h":
				if(params.length != 1) {
					System.out.println("Incorrect usage of " + params[0]);
					System.out.println("Type \"help\" for a list of commands and their usage.");
				} else {
					display_help();
				}
				break;
			case "exit":
			case "x":
				if(params.length != 1) {
					System.out.println("Incorrect usage of " + params[0]);
				} else if(socket != null) {
					System.out.println("Please end your secure session before exiting the client.");
				} else {
					finished = true;
				}
				break;
			case "start-ssession":
			case "s":
				if(params.length != 2) {
					System.out.println("Incorrect usage of " + params[0]);
					System.out.println("Type \"help\" for a list of commands and their usage.");
				} else if(socket != null) {
					System.out.println("Please exit your current secure session before initiating a new one.");
				} else {
					start_ssession(params[1]);
				}
				break;
			case "end-ssession":
			case "e":
				if(params.length != 1) {
					System.out.println("Incorrect usage of " + params[0]);
					display_help();
				} else if(socket == null) {
					System.out.println("No session currently active.");
				} else {
					end_ssession();
				}
				break;
			case "put":
			case "p":
				if(params.length != 3) {
					System.out.println("Incorrect usage of " + params[0]);
					System.out.println("Type \"help\" for a list of commands and their usage.");
				} else if(socket == null) {
					System.out.println("You must start a session to upload a document.");
				} else {
					File f = new File(params[1]);
					if(!f.exists()) {
						System.out.println("Document " + params[1] + " does not exist.");
					} else if(!security_flag_options.contains(params[2].toUpperCase())) {
						System.out.println("Invalid security flag: " + params[2]);
					} else {
						put(params[1], params[2].toUpperCase());
					}
				}
				break;
			case "get":
			case "g":
				if(params.length != 2) {
					System.out.println("Incorrect usage of " + params[0]);
					System.out.println("Type \"help\" for a list of commands and their usage.");
				} else if(socket == null) {
					System.out.println("You must start a session to retrieve a document.");
				} else {
					get(params[1]);
				}
				break;
			case "delegate":
			case "d":
				if(params.length != 6) {
					System.out.println("Incorrect usage of " + params[0]);
					System.out.println("Type \"help\" for a list of commands and their usage.");
				} else if(socket == null) {
					System.out.println("You must start a session to delegate a document.");
				} else {
					if(!Pattern.matches("\\d+", params[3])) {
						System.out.println("Invalid time format: " + params[3]);
					} else if(Integer.parseInt(params[3]) == 0) {
						System.out.println("Cannot delegate a document for 0 seconds.");
					} else if(!propagation_flag_options.contains(params[4])) {
						System.out.println("Invalid propagation flag: " + params[4]);
					} else if(!Pattern.matches("get|put|both", params[5])) {
						System.out.println("Invalid delegation type: " + params[5]);
					} else {
						delegate(params[1], params[2], Integer.parseInt(params[3]),
								Boolean.parseBoolean(params[4]), params[5]);
					}
				}
				break;
			// Syntax error on command
			default:
				System.out.println("Invalid command: " + params[0]);
				System.out.println("Type \"help\" for a list of commands and their usage.");
			}
		} while(!finished);
		
		// Clean up and exit the SDDR client
		System.out.println("Exiting SDDR client...");
		user_input.close();
	}
}
