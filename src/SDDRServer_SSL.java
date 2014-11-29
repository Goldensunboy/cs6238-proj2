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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.acl.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

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
			String filename = in.readLine();
			System.out.println("Filename is " + filename);
			// creating the file on server
			File file = new File(filename); // renaming the file while put...just for visibility
			if (file.exists()) {
				System.out.println("File " + filename + " already exists...OVERWRITING \n ");
			}
			
			//receiving the filesize
			String reply = in.readLine();
			int filesize = Integer.parseInt(reply);
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
			
			// If the user is not authenticated to open this file, reject
			// TODO
			
			// Get the file information, send length to user
			int filesize = (int) f.length();
			out.write(filesize + "\n");
			out.flush();
			
			// Send the file
			byte filebytes[] = new byte[filesize];
			FileInputStream fis = new FileInputStream(f);
			BufferedInputStream bis = new BufferedInputStream(fis);
			bis.read(filebytes, 0, filesize);
			bis.close();
			fis.close();
			dout.write(filebytes, 0, filesize);
			dout.flush();
			
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
			
			// Receive commands from client until user ends the session
			do {
				String command = in.readLine();
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
			in.close();
			out.close();
		} catch(IOException e) {
			System.out.println("Connection to user " + clientname + " interrupted: " + e.getMessage());
		} catch (KeyStoreException e) {
			System.out.println("Keystore exception occured");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
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
