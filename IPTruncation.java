package anonymisering;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class IPTruncation {
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<List<String>> newlog;
	
	public IPTruncation(String logType, String inputFile, String outputFile) throws FileNotFoundException {
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		assignType(logType);
		toTextFile(outputFile);
	}
	
	public void assignType(String logType) {
		newlog = log;
		if(logType.equalsIgnoreCase("ipv4")) {
			newlog = truncation(14);
			newlog = truncation(15);
		}
		else if(logType.equalsIgnoreCase("ipv6")) {
			newlog = truncation(7);
			newlog = truncation(8);
		}
		else if(logType.equalsIgnoreCase("netflow")) {
			newlog = truncation(4);
			newlog = truncation(5);
		}
		else if(logType.equalsIgnoreCase("webserver")) {
			newlog = truncation(0);
		}
		
	}
	
	public ArrayList<List<String>> truncation(int index){
		ArrayList<List<String>> newLog = new ArrayList<List<String>>();
		for(List<String> pkt : newlog) {
			if(pkt.get(index).contains(".")) {
				String[] octets = pkt.get(index).split("\\.");
				List<String> newpkt = new ArrayList<String>();
				for(int i = 0; i < index;i++) {
					newpkt.add(pkt.get(i));
				}
				newpkt.add(octets[0]+"."+octets[1]+"."+octets[2]+".0");
				for(int i = index + 1; i < pkt.size(); i++) {
					newpkt.add(pkt.get(i));
				}
				newLog.add(newpkt);
			}
			else if(pkt.get(index).contains(":")){
				String[] hexas = pkt.get(index).split("\\:");
				List<String> newpkt = new ArrayList<String>();
				for(int i = 0; i < index;i++) {
					newpkt.add(pkt.get(i));
				}
				newpkt.add(hexas[0]+":"+hexas[1]+":"+hexas[2]+":"+hexas[3]+":"+hexas[4]+":"+hexas[5]+":"+hexas[6]+":0");
				for(int i = index + 1; i < pkt.size(); i++) {
					newpkt.add(pkt.get(i));
				}
				newLog.add(newpkt);
			}
			else {
				newLog.add(pkt);
			}
		}
		return newLog;
	}
	
	//Method to write lines from the feature selected pkts to file.
		public void toTextFile(String FNAME) {
			ArrayList<String> format = new ArrayList<>();
			for(List<String> pkt : newlog) {
				String samlet = "";
				for(String field : pkt) {
					samlet += field + "\t"; 
				}
				format.add(samlet + "\n");
			}
			
			try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) 
			{
				for (String line : format) {
					bw.write(line);// + "\n");
				}
				System.out.println("Created file " + FNAME);
				bw.close ();
				
			} catch (IOException e) {
				e.printStackTrace ();
			}
		}
		
		
		public static void main(String[] args) throws FileNotFoundException {
//			IPTruncation g = new IPTruncation("webserver", 
//					"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Webserver\\O2-Webserver.dat",
//					"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Webserver\\A-Tr-Webserver.dat");
			if (args.length !=3) {
			      System.err.println("usage: java -jar jarfile.jar logtype originalInput.dat anonymizedInput.dat \n"
			    		  + "The logtype must be either IPv4, IPv6, Netflow or Webserver");
			      System.exit(-1);
			    }
			else {
				IPTruncation rs = new IPTruncation(args[0],args[1],args[2]);
			}
		}
	

}
