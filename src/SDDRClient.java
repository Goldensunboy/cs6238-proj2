import java.util.regex.Pattern;

/**
 * Secure Distributed Data Repository Client
 * @author Andrew Wilder, Prabhendu Pandey
 */
public class SDDRClient {
	
	/**
	 * Main client method to run after arguments are validated.
	 * Connect to a server and start a secure session.
	 * @param server_ip The IP of the server
	 * @param server_port The port number to connect to on the server
	 */
	private static void sddrclient_main(String server_ip, int server_port) {
		System.out.printf("Connecting to %s:%d...\n", server_ip, server_port);
	}
	
	/**
	 * Terminate the SDDR client with an error message
	 * @param message What went wrong
	 */
	private static void sddrclient_fail(String message) {
		System.out.println(message);
		System.exit(1);
	}
	
	/**
	 * Validate the arguments, and call the SDDR client main
	 * @param args The server IP and port to connect to
	 */
	public static void main(String[] args) {
		if(args.length != 2) {
			sddrclient_fail("Program usage: java SDDRClient <ip> <port>");
		}
		if(!Pattern.matches("\\d+(\\.\\d+){3}", args[0])) {
			sddrclient_fail("Invalid IP: " + args[0]);
		}
		String[] digits = args[0].split("\\.");
		for(int i = 0; i < digits.length; ++i) {
			if(Integer.parseInt(digits[i]) > 255) {
				sddrclient_fail("IP field out of range: " + digits[i]);
			}
		}
		if(!Pattern.matches("\\d+", args[1])) {
			sddrclient_fail("Invalid port: " + args[1]);
		}
		if(Integer.parseInt(args[1]) >= 1 << 16) {
			sddrclient_fail("Port out of range: " + args[1]);
		}
		sddrclient_main(args[0], Integer.parseInt(args[1]));
	}
}
