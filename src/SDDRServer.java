import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.regex.Pattern;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * Secure Distributed Data Repository Server
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRServer extends Thread {
	
	/**
	 * Main server method to run after arguments are validated.
	 * Bind to a port for initiating secure sessions with clients.
	 */
	private Socket socket;
	public void run() {
		System.out.println("Connected to user " + socket.getInetAddress().toString().substring(1) +
				":" + socket.getPort() + "!");
		try {
			// Get input and output handles for client communication
			BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter writer = new PrintWriter(socket.getOutputStream());
			
			// Initiate secure session with client
			
		} catch(IOException e) {
			sddrserver_fail("Server encountered an error: " + e.getMessage());
		}
	}
	
	/**
	 * Create a new SDDR Server
	 * @param socket The socket to communicate with the client
	 */
	public SDDRServer(Socket socket) {
		this.socket = socket;
		System.out.println("Accepted connection from " + socket.getInetAddress() + ":" + socket.getPort());
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
		if(args.length != 1) {
			sddrserver_fail("Program usage: java SDDRServer <port>");
		}
		if(!Pattern.matches("\\d+", args[0])) {
			sddrserver_fail("Invalid port: " + args[0]);
		}
		if(Integer.parseInt(args[0]) >= 1 << 16) {
			sddrserver_fail("Port out of range: " + args[0]);
		}
		ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
		ServerSocket ss = null;
		try {
			ss = ssf.createServerSocket(Integer.parseInt(args[0]));
			System.out.println("Listening for incoming connections on port " + args[0] + "...");
			while(true) {
				new SDDRServer(ss.accept()).start();
			}
		} catch(IOException e) {
			sddrserver_fail("Server encountered an error: " + e.getMessage());
		}
	}
}
