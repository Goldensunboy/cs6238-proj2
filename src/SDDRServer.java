import java.util.regex.Pattern;

/**
 * Secure Distributed Data Repository Server
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRServer {
	
	/**
	 * Main server method to run after arguments are validated.
	 * Bind to a port for initiating secure sessions with clients.
	 * @param server_ip The IP of the server
	 * @param server_port The port number to connect to on the server
	 */
	private static void sddrserver_main(int server_port) {
		System.out.printf("Binding to port %d...\n", server_port);
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
	 * Validate the argument, and call the SDDR server main
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
		sddrserver_main(Integer.parseInt(args[0]));
	}
}
