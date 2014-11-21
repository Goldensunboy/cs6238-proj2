import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * Secure Distributed Data Repository Client
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRClient {
	
	private static final boolean DEBUG = true;
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
		SocketFactory socketFactory = SSLSocketFactory.getDefault();
	    try {
	    	// Initiate connection
			socket = socketFactory.createSocket(hostname, SDDR_PORT);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			din = new DataInputStream(socket.getInputStream());
		    out = new PrintWriter(socket.getOutputStream());
		} catch (IOException e) {
			System.out.println("Failed to initiate connection: " + e.getMessage());
			in = null;
			din = null;
			out = null;
			socket = null;
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
		out.write("end-ssession\n");
		out.flush();
		
		// Attempt to close the communication socket
		try {
			socket.close();
			in.close();
			din.close();
			out.close();
		} catch(IOException e) {
			System.out.println("Error closing connection: " + e.getMessage());
			return;
		}
		
		// Set fields to null since they are invalidated now
		hostname = null;
		socket = null;
		in = null;
		out = null;
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
		
		// Send command to server
		out.write("put\n");
		out.flush();
		
		// TODO
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
			out.write("get\n" + document + '\n');
			out.flush();
			
			// Get message from server
			String reply = in.readLine();
			
			// Does the file exist?
			if(DOES_NOT_EXIST.equals(reply)) {
				System.out.println("File \"" + document + "\" does not exist.");
				return;
			}
			
			// Does the user have permission to get this file?
			// TODO
			
			// Get the file
			int filesize = Integer.parseInt(reply);
			byte filebytes[] = new byte[filesize];
			int bytesread = 0;
			while(bytesread < filesize) {
				int thisread = din.read(filebytes, bytesread, filesize - bytesread);
				if(thisread >= 0) {
					bytesread += thisread;
				} else {
					System.out.println("Encountered an error while downloading file");
				}
			}
			
			// Write the file
			File f = new File(document);
			if(f.exists()) {
				f.delete();
			}
			FileOutputStream fos = new FileOutputStream(f);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			bos.write(filebytes, 0, filesize);
			bos.flush();
			bos.close();
			fos.close();
			
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
	private static void delegate(String document, String client, int time, boolean propagation_flag) {
		System.out.println("Delegating " + document + " to " + client + " with flag " + propagation_flag +
				" for " + time + " seconds...");
		
		// Send command to server
		out.write("delegate\n");
		out.flush();
		
		// TODO
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
				"\t(d)elegate <document> <client> <time> <propflag>\n" +
				"\t\tAllows delegation of document to client for time seconds.\n" +
				"\t\tIf client is ALL, delegate to everyone.\n" +
				"\t\t\tpropflag: true  : Users may propagate delegation rights of file via delegate command\n" +
				"\t\t\t          false : Users may not propagate delegation rights");
	}
	
	/**
	 * SDDR client main.
	 * While the user hasn't exited, allow connection to SDDR servers.
	 * During connection, allow upload, download and delegation of files.
	 * @param args Unused
	 */
	private static String hostname = null;
	private static Socket socket = null;
	private static BufferedReader in = null;
	private static DataInputStream din = null;
	private static PrintWriter out = null;
	public static void main(String[] args) {
		
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
					} else if(!security_flag_options.contains(params[2])) {
						System.out.println("Invalid security flag: " + params[2]);
					} else {
						put(params[1], params[2]);
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
				if(params.length != 5) {
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
					} else {
						delegate(params[1], params[2], Integer.parseInt(params[3]),
								Boolean.parseBoolean(params[4]));
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
