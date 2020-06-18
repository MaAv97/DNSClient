package DNSClient;

import java.io.IOException;

public class Main {
	
	
	public DNSClient dnsClient;
	public static String domain="www.tuiasi.ro";
	
	
	
	public static void main(String[] args) throws IOException{
	
		DNSClient dnsClient = new DNSClient();
		String IPv4 = "";
		IPv4 = dnsClient.getIP(domain);
		
	}



}
