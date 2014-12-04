import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.Timer;
import java.util.TimerTask;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;

/**
 * Secure Distributed Data Repository Server
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRServer extends Thread {
	
	private static final String DOES_NOT_EXIST = "does_not_exist";
	private static final String DATA_FOLDER = "sddr_filedata";
	private static final String META_FOLDER = "sddr_metadata";
	private static final String META_EXT = ".meta";
	
	// Class to store values for a particular file
	private static class FileValues {
		private String owner = null;
		private byte[] aesEncKey = null;
		private String secflag = null;
		private byte[] realsign = null;
		private int    filesize = 0;
		
		public FileValues(String owner, byte[] aesEncKey, String secflag, byte[] realsign, int filesize) {
			this.owner = owner;
			this.aesEncKey = aesEncKey;
			this.secflag = secflag;
			this.realsign = realsign;
			this.filesize = filesize;
		}
	}
	
	// List of active delegations
	private volatile static List<DelegationRights> delegations = new ArrayList<DelegationRights>();
	
	// Class to store delegation properties
	private static class DelegationRights {
		//private String owner = null;
		private String recipient = null;
		private String document;
		private Timer tm = null;
		private int ID = 0;
		private static int GLOBAL_ID = 0;
		private boolean delegation = false;
		private boolean canGet = true, canPut = true;
		
		public DelegationRights(String recipient, String document, int seconds, boolean delegation, String delegationType) {
			this.recipient = recipient;
			this.document = document;
			ID = GLOBAL_ID++;
			this.delegation = delegation;
			tm = new Timer();
			if("get".equals(delegationType)) {
				canPut = false;
			} else if("put".equals(delegationType)) {
				canGet = false;
			}
			
			tm.schedule(new TimerTask() {
				public void run() {
					DelegationRights toRemove = null;
					for(DelegationRights dr : delegations) {
						if(dr.ID == ID) {
							toRemove = dr;
						}
					}
					delegations.remove(toRemove);
					System.out.println("Delegation rights to " + toRemove.document + " for " + toRemove.recipient + " have ended.");
				}
			}, seconds * 1000);
		}
		
		public boolean equals(Object o) {
			if(o instanceof DelegationRights) {
				return ((DelegationRights) o).ID == ID;
			} else {
				return false;
			}
		}
		
		public String toString() {
			return "Recipient: " + recipient + " Document: " + document + " ID: " + ID + " Propagation: " + delegation;
		}
	}
	
	/**
	 * Check if a particular user has delegation rights
	 * @param user The user to check for
	 * @return True if this user has delegation rights
	 */
	private boolean hasDelegationRights(String user, String document, String delegationType) {
		for(DelegationRights dr : delegations) {
			if(document.equals(dr.document)) {
				if("ALL".equals(dr.recipient) || user.equals(dr.recipient)) {
					if(delegationType.equals("get") && dr.canGet) {
						return true;
					} else if(delegationType.equals("put") && dr.canPut) {
						return true;
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * Check if a particular user has delegation rights and propagation flag
	 * @param user The user to check for
	 * @return True if this user has delegation rights
	 */
	private boolean hasDelegationRightsWithProp(String user, String document, String delegationType) {
		for(DelegationRights dr : delegations) {
			if(document.equals(dr.document)) {
				if("ALL".equals(dr.recipient) || user.equals(dr.recipient)) {
					if(dr.delegation) {
						if(delegationType.equals("get") && dr.canGet) {
							return true;
						} else if(delegationType.equals("put") && dr.canPut) {
							return true;
						} else if(dr.canGet && dr.canPut) { // "both"
							return true;
						}
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * Get file values 
	 * @param filename
	 * @return
	 */
	private static FileValues getFileValues(String filename) {
		File f = new File(META_FOLDER + "/" + filename + META_EXT);
		if(f.exists()) {
			try {
				Scanner scan = new Scanner(f);
				scan.useDelimiter(",|\n");
				String owner = scan.next();
				String aesEncKey_str = scan.next();
				String secflag = scan.next();
				String realsign_str = scan.next();
				byte[] aesEncKey = new byte[aesEncKey_str.length() >> 1];
				for(int i = 0; i < aesEncKey_str.length(); i += 2) {
					char c0 = aesEncKey_str.charAt(i + 1);
					char c1 = aesEncKey_str.charAt(i);
					int val = c0 > '9' ? c0 - 'A' + 10 : c0 - '0';
					val += (c1 > '9' ? c1 - 'A' + 10 : c1 - '0') << 4;
					aesEncKey[i >> 1] = (byte) val;
				}
				byte[] realsign = new byte[realsign_str.length() >> 1];
				for(int i = 0; i < realsign_str.length(); i += 2) {
					char c0 = realsign_str.charAt(i + 1);
					char c1 = realsign_str.charAt(i);
					int val = c0 > '9' ? c0 - 'A' + 10 : c0 - '0';
					val += (c1 > '9' ? c1 - 'A' + 10 : c1 - '0') << 4;
					realsign[i >> 1] = (byte) val;
				}
				int filesize = Integer.parseInt(scan.next());
				scan.close();
				return new FileValues(owner, aesEncKey, secflag, realsign, filesize);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/** Port that SDDR server always binds to */
	private static final int SDDR_PORT = 40231;
	
	/**
	 * put(Document UID, SecurityFlag): A document is sent to the server over the secure channel that was 
	 * established when the session was initiated. If the document already exists on the server, you may 
	 * overwrite it along with its meta-data. If a new document is put, this client becomes the owner of the 
	 * document. If the client is able to update because of a delegation, the owner does not change. You need to 
	 * use some scheme to ensure that documents created by different clients have unique UIDs. The 
	 * SecurityFlag specifies how document data should be stored on the server
	 */
	private void put() {
		System.out.println("Received command from " + clientname + ": put");
		
		try {
			// Get document name
			String document = sddr_in.readString();
			
			// Get security flag
			String secflag = sddr_in.readString();
			
			// Verify that the user has permission to write this file
			File document_file = new File(DATA_FOLDER + "/" + document);
			if(document_file.createNewFile()) {
				sddr_out.writeString("SUCCESS");
			} else {
				FileValues fv = getFileValues(document);
				if(user_alias.equals(fv.owner)) {
					sddr_out.writeString("SUCCESS");
				} else {
					if(hasDelegationRights(user_alias, document, "put")) {
						sddr_out.writeString("SUCCESS");
					} else {
						sddr_out.writeString("FAILURE");
						return;
					}
				}
			}
			
			// Recieve the file from the user
			byte[] filedata = sddr_in.readData();
			int filesize = filedata.length;
			
			// If confidential, encrypt data as well
			byte[] aes_encrypted = new byte[2];
			byte[] realsign = new byte[2];
			if("CONFIDENTIAL".equals(secflag)) {
				// Generate random AES key
				KeyGenerator keygen = KeyGenerator.getInstance("AES");
				keygen.init(128);
				byte[] aesKeyBytes = keygen.generateKey().getEncoded();
				
				// Encrypt using the key
				Cipher c = Cipher.getInstance("AES");
				SecretKeySpec ks = new SecretKeySpec(aesKeyBytes, "AES");
				c.init(Cipher.ENCRYPT_MODE, ks);
				filedata = c.doFinal(filedata);
				
				// Encrypt the AES key
				c = Cipher.getInstance("RSA");
				c.init(Cipher.ENCRYPT_MODE, pubkey);
				aes_encrypted = c.doFinal(aesKeyBytes);
				
			} else if("INTEGRITY".equals(secflag)) {
				// Signing the document using private key of server
				Signature dsa = Signature.getInstance("SHA1withRSA");
				dsa.initSign(privkey);
				dsa.update(filedata); // filebytes contain the data of file in byte[] format
				realsign = dsa.sign();
			}
			
			// Write the file contents
			FileOutputStream fos = new FileOutputStream(document_file);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			bos.write(filedata);
			bos.flush();
			
			// Write the metadata contents
			FileWriter fw = new FileWriter(new File(META_FOLDER + "/" + document + META_EXT));
			fw.write(user_alias);
			fw.write(",");
			for(int i = 0; i < aes_encrypted.length; ++i) {
				byte val = aes_encrypted[i];
				int low = ((int) val) & 0xF;
				int high = ((int) val) >> 4 & 0xF;
				String byte_str = "" + (char)(high > 9 ? 'A' + (high - 10) : '0' + high);
				byte_str += (char)(low > 9 ? 'A' + (low - 10) : '0' + low);
				fw.write(byte_str);
			}
			fw.write(",");
			fw.write(secflag);
			fw.write(",");
			for(int i = 0; i < realsign.length; ++i) {
				byte val = realsign[i];
				int low = ((int) val) & 0xF;
				int high = ((int) val) >> 4 & 0xF;
				String byte_str = "" + (char)(high > 9 ? 'A' + (high - 10) : '0' + high);
				byte_str += (char)(low > 9 ? 'A' + (low - 10) : '0' + low);
				fw.write(byte_str);
			}
			fw.write(",");
			fw.write("" + filesize);
			fw.write("\n");
			
			// Close file streams
			bos.close();
			fw.close();
		
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
	private void get() {
		System.out.println("Received command from " + clientname + ": get ");
		
		try {
			// Receive the file name
			String document = sddr_in.readString();
			//System.out.println("Client issued command: get " + filename);
			
			// If the file doesn't exist, return an error message
			if(!new File(DATA_FOLDER + "/" + document).exists()) {
				sddr_out.writeString(DOES_NOT_EXIST);
				System.out.println("User attempted to retrieve file that doesn't exist: " + document);
				return;
			} else {
				sddr_out.writeString("EXISTS");
			}
			
			// Determine if the user can open this document
			FileValues fv = getFileValues(document);
			
			if(user_alias.equals(fv.owner)) {
				sddr_out.writeString("SUCCESS");
			} else {
				if(hasDelegationRights(user_alias, document, "get")) {
					sddr_out.writeString("SUCCESS");
				} else {
					sddr_out.writeString("FAILURE");
					return;
				}
			}
			
			// Read file into byte array
			File file = new File(DATA_FOLDER + "/" + document);
			int filesize = (int) file.length();
			byte filebytes[] = new byte[filesize];
			FileInputStream fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(filebytes, 0, filesize);
			bis.close();
			fis.close();
			
			// If the file is encrypted, decrypt it
			if("CONFIDENTIAL".equals(fv.secflag)) {
				// Decrypt the AES key
				Cipher skCipher = Cipher.getInstance("RSA");
				skCipher.init(Cipher.DECRYPT_MODE, privkey);
				byte[] aesKey = skCipher.doFinal(fv.aesEncKey);
				
				// Decrypt the file
				SecretKeySpec keySpec = new SecretKeySpec(aesKey,"AES");
				Cipher sCipher = Cipher.getInstance("AES");
			    sCipher.init(Cipher.DECRYPT_MODE, keySpec);
			    byte[] plainText = new byte[sCipher.getOutputSize(filesize)];
			    int ptLength = sCipher.update(filebytes, 0, filesize, plainText, 0);
			    ptLength += sCipher.doFinal(plainText, ptLength);
			    filebytes = plainText;
			    
			    sddr_out.writeString("OKAY");
				
			} else if("INTEGRITY".equals(fv.secflag)) {
				// Check if the sign is correct
				Signature sign = Signature.getInstance("SHA1withRSA");
				sign.initVerify(pubkey);
				sign.update(filebytes, 0, filesize);
				boolean verifies = sign.verify(fv.realsign);
				
				if(verifies) {
					sddr_out.writeString("OKAY");
				} else {
					sddr_out.writeString("TAMPERED");
				}
			} else { // NONE
				sddr_out.writeString("OKAY");
			}

			// Send file to user
			sddr_out.writeData(Arrays.copyOf(filebytes, "CONFIDENTIAL".equals(fv.secflag) ? fv.filesize : filesize));
			
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
	private void delegate() {
		System.out.println("Received command from " + clientname + ": delegate");
		
		// Get the document name
		String document = sddr_in.readString();
		
		// Get the client name
		String client = sddr_in.readString();
		
		// Get the delegation time
		int time = Integer.parseInt(sddr_in.readString());
		
		// Get the propagation flag
		boolean propagation_flag = Boolean.parseBoolean(sddr_in.readString());
		
		// Get the delegation type
		String delegationType = sddr_in.readString();
		
		// Can user delegate this file?
		FileValues fv = getFileValues(document);
		if(user_alias.equals(fv.owner)) {
			sddr_out.writeString("SUCCESS");
		} else {
			if(hasDelegationRightsWithProp(user_alias, document, delegationType)) {
				sddr_out.writeString("SUCCESS");
			} else {
				sddr_out.writeString("FAILURE");
				return;
			}
		}
		
		// Create delegation for this user
		delegations.add(new DelegationRights(client, document, time, propagation_flag, delegationType));
	}
	
	/**
	 * Main server method to run after arguments are validated.
	 * Bind to a port for initiating secure sessions with clients.
	 */
	private Socket socket = null;
	private String clientname = null;
	private DataInputStream in = null;
	private DataOutputStream out = null;
	private SDDRDataReader sddr_in = null;
	private SDDRDataWriter sddr_out = null;
	private String user_alias = null;
	public void run() {
		System.out.println("Connection request from user " + clientname + ":" + socket.getPort());
		
		// Fields used to handle the client connection
		boolean finished = false;
		
		try {
			// Get unencrypted input and output handles for key exchange
			in = new DataInputStream(socket.getInputStream());
			out = new DataOutputStream(socket.getOutputStream());
			ObjectInputStream objin = new ObjectInputStream(socket.getInputStream());
		    ObjectOutputStream objout = new ObjectOutputStream(socket.getOutputStream());
		    
		    // Step 1: Receive client alias
		    user_alias = (String) objin.readObject();
		    Certificate cert = keystore.getCertificate(user_alias);
			PublicKey client_key = cert.getPublicKey();
		    
		    // Step 2: Send server alias
		    objout.writeObject(keyfile_server_creds);
		    
		    // Step 3: Receive Pub_S[K] from client
		    int K_len = in.readInt();
		    byte[] K_encrypted = new byte[K_len];
		    int bytes_received = 0;
		    while(bytes_received < K_len) {
		    	int this_read = in.read(K_encrypted, bytes_received, K_len - bytes_received);
		    	if(this_read == -1) {
		    		throw new Exception("Connection error");
		    	} else {
		    		bytes_received += this_read;
		    	}
		    }
		    Cipher c = Cipher.getInstance("RSA");
		    c.init(Cipher.DECRYPT_MODE, privkey);
		    byte[] K_bytes = c.doFinal(K_encrypted);
		    int K = ByteBuffer.wrap(K_bytes).getInt();

		    // Step 4: Send Pub_C[X] to client
		    int X = new Random().nextInt();
		    byte[] X_bytes = ByteBuffer.allocate(4).putInt(X).array();
		    c.init(Cipher.ENCRYPT_MODE, client_key);
		    byte[] X_encrypted = c.doFinal(X_bytes);
		    out.writeInt(X_encrypted.length);
		    out.write(X_encrypted);
		    
		    // Step 5: Receive Pub_S[X+1] from client
		    int Xplusone_len = in.readInt();
		    byte[] Xplusone_encrypted = new byte[Xplusone_len];
		    bytes_received = 0;
		    while(bytes_received < Xplusone_len) {
		    	int this_read = in.read(Xplusone_encrypted, bytes_received, Xplusone_len - bytes_received);
		    	if(this_read == -1) {
		    		throw new Exception("Connection error");
		    	} else {
		    		bytes_received += this_read;
		    	}
		    }
		    c.init(Cipher.DECRYPT_MODE, privkey);
		    byte[] Xplusone_bytes = c.doFinal(Xplusone_encrypted);
		    int Xplusone = ByteBuffer.wrap(Xplusone_bytes).getInt();
		    
		    // Step 6: Send Pub_C[K+1] to client
		    K++;
		    K_bytes = ByteBuffer.allocate(4).putInt(K).array();
		    c.init(Cipher.ENCRYPT_MODE, client_key);
		    K_encrypted = c.doFinal(K_bytes);
		    out.writeInt(K_encrypted.length);
		    out.write(K_encrypted);
		    
		    // Step 7: Receive ACK/NACK from client
		    String msg = (String) objin.readObject();
		    
		    // Step 8: Send ACK/NACK to client
		    String reply = "FAILURE".equals(msg) ? "CLIENT_FAILURE" : X + 1 == Xplusone ? "SUCCESS" : "FAILURE";
		    objout.writeObject(reply);
		    
		    if("FAILURE".equals(msg)) {
		    	throw new Exception("Client failed to verify server");
		    } else if(X + 1 != Xplusone) {
		    	throw new Exception("Server failed to authenticate client");
		    }
		    
		    // Step 9: Receive session key
		    int shared_key_encrypted_length = in.readInt();
			byte[] shared_key_encrypted = new byte[shared_key_encrypted_length];
			bytes_received = 0;
			while(bytes_received < shared_key_encrypted_length) {
				int this_read = in.read(shared_key_encrypted, bytes_received,
						shared_key_encrypted_length - bytes_received);
				if(this_read == -1) {
		    		throw new Exception("Connection error");
		    	} else {
		    		bytes_received += this_read;
		    	}
			}
			c.init(Cipher.DECRYPT_MODE, privkey);
			byte[] shared_key = c.doFinal(shared_key_encrypted);
			
			// Create secure reader and writer
			sddr_in = new SDDRDataReader(socket.getInputStream(), shared_key);
			sddr_out = new SDDRDataWriter(socket.getOutputStream(), shared_key);
			
			// Receive commands from client until user ends the session
			do {
				String command = sddr_in.readString();
//				if(DEBUG) System.out.println("\tCommand: " + command);
				switch(command) {
				case "end-ssession":
					finished = true;
					break;
				case "put":
					put();
					break;
				case "get":
					get();
					break;
				case "delegate":
					delegate();
					break;
				default:
					System.out.println("Unknown command received: " + command);
				}
			} while(!finished);
			if(in != null) {
				in.close();
			}
			if(out != null) {
				out.close();
			}
			if(sddr_in != null) {
				sddr_in.close();
			}
			if(sddr_out != null) {
				sddr_out.close();
			}
		} catch(Exception e) {
			System.out.println("Connection to user " + clientname + " interrupted: " + e.getMessage());
			e.printStackTrace();
			try {
				if(in != null) {
					in.close();
				}
				if(out != null) {
					out.close();
				}
				if(sddr_in != null) {
					sddr_in.close();
				}
				if(sddr_out != null) {
					sddr_out.close();
				}
			} catch (IOException ioe) {
				e.printStackTrace();
			}
		}
		System.out.println("Ended connection with user " + socket.getInetAddress().toString().substring(1) +
				":" + socket.getPort() + ".");
	}
	
	/**
	 * Create a new SDDR Server
	 * @param socket The socket to communicate with the client
	 */
	public SDDRServer(Socket socket) {
		this.socket = socket;
		clientname = socket.getInetAddress().toString().substring(1);
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
	private static PublicKey pubkey = null;
	private static PrivateKey privkey = null;
	private static String keyfile;
	private static String keyfile_pass;
	private static String keyfile_server_creds;
	private static File dataFolder;
	private static File metaFolder;
	private static KeyStore keystore;
	public static void main(String[] args) {
		
		if(args.length != 3) {
			System.out.println("Incorrect usage of the server: Expecting args <keystore> <password> <srvname>");
			System.exit(1);
		}
		
		// Set the keystore information
		keyfile = args[0];
		keyfile_pass = args[1];
		keyfile_server_creds = args[2];
		
		try {
			// Get server keys
			FileInputStream keyStoreFileStream = new FileInputStream(keyfile);
			keystore = KeyStore.getInstance("JKS");
			keystore.load(keyStoreFileStream, keyfile_pass.toCharArray());
			Certificate cert = keystore.getCertificate(keyfile_server_creds);
			pubkey = cert.getPublicKey();
			privkey = (PrivateKey) keystore.getKey(keyfile_server_creds, keyfile_pass.toCharArray());
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// Create file and metadata folders
		dataFolder = new File(DATA_FOLDER);
		if(!dataFolder.exists()) {
			dataFolder.mkdir();
		}
		metaFolder = new File(META_FOLDER);
		if(!metaFolder.exists()) {
			metaFolder.mkdir();
		}

		ServerSocketFactory ssf = ServerSocketFactory.getDefault();
		ServerSocket ss = null;
		try {
			ss = ssf.createServerSocket(SDDR_PORT);
			System.out.println("Listening for incoming connections on port " + SDDR_PORT + "...");
			while(true) {
				new SDDRServer(ss.accept()).start();
			}
		} catch(IOException e) {
			sddrserver_fail("Server encountered an error: " + e.getMessage());
		}
	}
}
