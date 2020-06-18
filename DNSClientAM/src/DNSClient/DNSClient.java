package DNSClient;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Random;

public class DNSClient {
	public static String userAgent="RIWEB_CRAWLER";
	public static int limitOfPages=100;
	public static int portUDP=53;
	public static String server="81.180.223.1";
	
	
	public void makeRequest(byte[] request, String domain) 
	{
		
		//Question Name -> lungimea este strlen() + 2 + 2 (QF) + 2 (QC)
		for(int i=0; i<12+ domain.length() + 6; i++) {
			request[i]=0x0;
		}
		
        Random r = new Random();
        int identifier = r.nextInt(1 << 16 - 1);
        
        request[0]=(byte)((identifier&0XFF00)>>8);
        request[1]=(byte) (identifier&0xFF);
        request[2]=0x00;
        request[3]=0x00;
        request[5]=0x01;
        
        char[] caractere= domain.toCharArray();
        int contor=0, indexPosition=12;
        for(int i=0; i<domain.length(); i++) // parsam domeniul si il stocam in formatul specific
        {
        	//daca nu am ajuns la punct
        	if(caractere[i]!='.') 
        	{
        		contor+=1;
        		request[contor+indexPosition]=(byte) caractere[i];
        	}
        	else 
        		//daca sunt pe punct atunci introduc eticheta
        	{
        		// setam numarul de caractere
        		request[indexPosition]=(byte)contor;
        		indexPosition+=contor+1;
        		contor=0;
        	}
        	 // daca am ajuns la final, punem si ultimele caractere
        	if(i==domain.length()-1) 
        	{
        		// setam numarul de caractere
        		request[indexPosition]=(byte)contor;
        		indexPosition+=contor;
        		contor=0;
        	}
        }
        indexPosition+=1;
     // Question Type -> 1 = adresa IP
        request[indexPosition+2]=0x01;
     // Question Class -> 1 = clasa internet
        request[indexPosition+4]=0x01;
	}
	
	public void printArrayByte(byte[] input) {
		for (int i = 0; i < input.length; ++i) {
            System.out.print('\t');
            System.out.print(String.format("[0x%02X]", input[i]));
            if ((i + 1) % 8 == 0) {
                System.out.println();
            }
        }
		 System.out.println();
	}
	
	public void getResponse(byte[] request, byte[] responseFromRequest) throws IOException {
		try {
			// construim un datagram cu destinatarul IP-ul serverului DNS, portul 53   
			DatagramSocket sock = new DatagramSocket();
            InetAddress IP = InetAddress.getByName(server);
            DatagramPacket req = new DatagramPacket(request, request.length, IP, portUDP);
         // trimitem pachetul la server-ul DNS
            sock.send(req);
            System.out.println("S-a trimis pachetul");
         // preluam raspunsul de la server
         // il punem intr-un buffer de 512 octeti
            DatagramPacket response = new DatagramPacket(responseFromRequest, 512);
            sock.receive(response);
            System.out.println("S-a primit pachetul");
            sock.close();
		} catch (SocketException e) {
			e.printStackTrace();
		}
	}
	
	public String checkResponse(byte[] response, byte[] request, String domain) {
		StringBuilder iPv4=new StringBuilder();
        if (response[0] == request[0] && response[1]==request[1])
        {
            System.out.println("Identificatorii se potrivesc");
        }
     // verificam validitatea raspunsului -> sa nu se fi produs vreo eroare
        /* adica octetul al 4-lea, RCode:
        [1 -> RA = 1 pentru ca e raspuns
        000 -> obligatoriu, pentru departajare
        0000] -> Response Code 0 inseamna ca nu avem erori pentru cerere si raspunsul e ceea ce am dorit
         */
        if ((response[3] & 0x0F) == 0x00)// ultimii 4 biti sunt codul de raspuns
        {
            System.out.println("Nicio eroare produsa: RCode 0 -> OK");
        } 
        else 
        {
            int errorCode = response[3] & 0x0F;
            System.out.println("S-a produs o eroare: RCode = " + errorCode);
        }
        // verificam numarul de raspunsuri primite (Answer Record Count)
        int numberResponse = ((0xFF & response[6]) << 8) | (0xFF & response[7]);
        System.out.println("Numarul de raspunsuri primite: " + numberResponse);
     // indicele octetului de unde incep Resource Records
     // pentru ca server-ul mentine informatiile din cererea clientului
        int responseID=0, indexPosition=12+domain.length()+6;
        while(responseID<numberResponse)
        {
        	
        	iPv4=new StringBuilder();
        	// preluam numele de particula recursiv
        	String resourceName=getPointer(indexPosition,response);
        	  // trebuie sa sarim peste un numar de octeti dependent de tipul de particula
        	// dimensiune de particula
        	if((response[indexPosition] & 0xFF)<192){
        		indexPosition+=resourceName.length()+1;
        	}
        	else // pointer
        	{
        		// pointer-ul e pe 2 octeti
        		indexPosition+=2;
        	}
        	System.out.println("Response ["+responseID+"] : " + resourceName);
        	System.out.println();
        	byte higher, lower;
        	
        	//get Record Type(2 octeti)
        	higher=response[indexPosition++];
        	lower=response[indexPosition++];
        	int typeOfRecord= (((0xFF) & higher) << 8) | (0xFF & lower);
        	if(typeOfRecord==1) 
        	{
        		System.out.println("Type Record: IPv4");
        	}
        	else if(typeOfRecord==5)
        	{
        		System.out.println("Type Record: Nume canonic");
        	}
        	
        	//get Record Class(2 octeti)
        	higher=response[indexPosition++];
        	lower=response[indexPosition++];
        	int classOfRecord= (((0xFF) & higher) << 8) | (0xFF & lower);
        	if(classOfRecord==1) 
        	{
        		System.out.println("Record Class: Internet");
        	}
        	
        	//Avoid 4 bytes(TTL bytes)
        	indexPosition+=4;
        	
        	//get data Length(2 octeti)
        	higher=response[indexPosition++];
        	lower=response[indexPosition++];
        	int lengthOfData= (((0xFF) & higher) << 8) | (0xFF & lower);
        	System.out.println("Data length : " + lengthOfData);
        	System.out.println();
        	// daca Data Length = 4, si Record Type = 1, raspunsul contine adresa IPv4
        	if(lengthOfData==4 && typeOfRecord==1) 
        	{
        		// construim adresa IPv4
        		for(int i=0; i<lengthOfData; i++) 
        		{
        			iPv4.append(response[indexPosition++] & 0xFF);
        			iPv4.append('.');
        			System.out.println(iPv4);
        		}
        		// stergem ultimul punct, pus in plus
        		iPv4.deleteCharAt(iPv4.length()-1);
        		System.out.println("Adresa IPv4: " + iPv4 );
        	}
        	else 
        	{
        		System.out.println("Unknown Record Type and Data Length");
        	}
        	responseID++;
        }
        return iPv4.toString();
	}
	  // functie care preia o particula de nume folosind un pointer sau o dimensiune de particula trimisa ca index
    // functia este recursiva, pentru ca putem avea pointeri la alti pointeri
   
    public String getPointer(int ipointer, byte[] buffer)
    {
    	// cat timp nu am ajuns la octetul terminator de nume
        if ((buffer[ipointer] & 0xFF) == 0x0)
        {
            return "";
        }
     // iar am gasit pointer
        if ((buffer[ipointer] & 0xFF) >= 192) 
        {
        	// calculam indicele de octet
            int newipointer = ((buffer[ipointer] & 0x3F) << 8) | (buffer[ipointer + 1] & 0xFF);
            return getPointer(newipointer, buffer);
        }
     // am ajuns pe dimensiune de particula, atunci construim sirul de caractere
        int currentNumberOfCharacters = buffer[ipointer++] & 0xFF;
        StringBuilder currentElement = new StringBuilder();
        for (int i = 0; i < currentNumberOfCharacters; ++i)
        {
        	// preluam cate o parte de particula
            currentElement.append((char)(buffer[ipointer+ i] & 0xFF));
        }
     // trecem la elementul urmator (daca exista)
        ipointer += currentNumberOfCharacters;
        return (currentElement.toString() + "." + getPointer(ipointer, buffer));
    }


    public static String getIP(String domain) throws IOException 
    {
		DNSClient dnsClient = new DNSClient();
		byte[] request = new byte[12 + domain.length() + 6];
		byte[] responseFromRequest = new byte[512];

		dnsClient.makeRequest(request, domain);
		System.out.println("Requst : ");
		dnsClient.printArrayByte(request);

		dnsClient.getResponse(request, responseFromRequest);
		System.out.println("Response : ");
		dnsClient.printArrayByte(responseFromRequest);

		String IPv4 = "";
		IPv4 = dnsClient.checkResponse(responseFromRequest, request, domain);
		return IPv4;
	}
    
}



