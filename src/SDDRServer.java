import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.net.ServerSocketFactory;

/**
 * Secure Distributed Data Repository Server
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRServer extends Thread {
	
	private static final boolean DEBUG = true;
	private static final String DOES_NOT_EXIST = "does_not_exist";
	
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
			// receive the file name
			String filename = sddr_in.readString();
			System.out.println("Filename is " + filename);
			// creating the file on server
			File file = new File(filename); // renaming the file while put...just for visibility
			if (file.exists()) {
				System.out.println("File " + filename + " already exists...OVERWRITING \n ");
			}
			
			//receiving the filesize
			int filesize = in.readInt();
			byte filebytes[] = sddr_in.readData();
			
			// Write the file on server
			FileOutputStream fos = new FileOutputStream(file);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			bos.write(filebytes, 0, filesize);
			bos.flush();
			bos.close();
			fos.close();

			System.out.println("File successfully received "+ filename + "\n");
			
		} catch(Exception e) {
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
	private void get() {
		System.out.print("Received command from " + clientname + ": get ");
		
		try {
			// Receive the file name
			String filename = sddr_in.readString();
			System.out.println("Client issued command: get " + filename);
			
			// If this file doesn't exist, return an error message
			File f = new File(filename);
			if(!f.exists()) {
				System.out.println("File " + filename + " does not exist.");
				sddr_out.writeString(DOES_NOT_EXIST);
				return;
			}
			
			// If the user is not authenticated to open this file, reject
			// TODO
			
			// Get the file information, send length to user
			int filesize = (int) f.length();
			sddr_out.writeString(filesize + "");
			
			// Send the file
			byte filebytes[] = new byte[filesize];
			FileInputStream fis = new FileInputStream(f);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(filebytes, 0, filesize);
			bis.close();
			fis.close();
			sddr_out.writeData(filebytes);
			
			System.out.println("Successfully sent " + filename);
			
		} catch (IOException e) {
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
	private DataInputStream in = null;
	private DataOutputStream out = null;
	private SDDRDataReader sddr_in = null;
	private SDDRDataWriter sddr_out = null;
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
			
			// Step 1: Get the public key of the client
		    PublicKey client_key = (PublicKey) objin.readObject();
			
			// Step 2: Send server key to client
		    objout.writeObject(pubkey);
			
			// Step 3: Receive shared secret
			int shared_secret_len = in.readInt();
			byte[] shared_secret_encrypted = new byte[shared_secret_len];
			int bytes_received = 0;
			while(bytes_received < shared_secret_len) {
				int this_read = in.read(shared_secret_encrypted, bytes_received,
						shared_secret_len - bytes_received);
				if(this_read == -1) {
		    		throw new Exception("Connection error");
		    	} else {
		    		bytes_received += this_read;
		    	}
			}
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, privkey);
			byte[] shared_secret = c.doFinal(shared_secret_encrypted);
			
			// Step 4: Send secret + 1 to client as an ACK
			int secretplusone = 0;
			for(int i = 0; i < 4; ++i) {
				secretplusone |= shared_secret[i] << (i << 3) & 0xFF << (i << 3);
			}
			++secretplusone;
			byte[] secretplusone_bytes = new byte[4];
			for(int i = 0; i < 4; ++i) {
				secretplusone_bytes[i] = (byte) (secretplusone >> (i << 3) & 0xFF);
			}
			c.init(Cipher.ENCRYPT_MODE, client_key);
			byte[] secretplusone_bytes_encrypted = c.doFinal(secretplusone_bytes);
			out.writeInt(secretplusone_bytes_encrypted.length);
			out.write(secretplusone_bytes_encrypted);
			
			// Step 4.5: Wait for Client ACK
			if(in.readInt() == 0x55555555) {
				System.out.println("Authentication verified!");
			} else {
				throw new Exception("Client could not verify Secret+1");
			}
			
			// Step 5: Receive AES session key
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
			sddr_in.close();
			sddr_out.close();
		} catch(Exception e) {
			System.out.println("Connection to user " + clientname + " interrupted: " + e.getMessage());
			e.printStackTrace();
			try {
				in.close();
				out.close();
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
	public static void main(String[] args) {
		
		try {
			// Get server keys
			FileInputStream keyStoreFileStream = new FileInputStream(args[0]);
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(keyStoreFileStream, args[1].toCharArray());
			Certificate cert = ks.getCertificate(args[2]);
			pubkey = cert.getPublicKey();
			privkey = (PrivateKey) ks.getKey(args[2], args[1].toCharArray());
			
			// Test server keys
			String msg = "Hello, world!";
			byte[] msg_bytes = msg.getBytes();
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, pubkey);
			byte[] msg_encrypted = c.doFinal(msg_bytes);
			c.init(Cipher.DECRYPT_MODE, privkey);
			byte[] msg_prime_bytes = c.doFinal(msg_encrypted);
			String msg_prime = new String(msg_prime_bytes, "UTF-8");
			System.out.println(msg_prime);
			
		} catch (Exception e) {
			e.printStackTrace();
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
