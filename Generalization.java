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

public class Generalization {
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<List<String>> newlog;
	
	public Generalization(String logType, String inputFile, String outputFile) throws FileNotFoundException {
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		assignType(logType);
		toTextFile(outputFile);
	}
	
	//Checks which log type is seleceted, and performs generalization.	
	public void assignType(String logType) {
		newlog = log;
		if(logType.equalsIgnoreCase("ipv4")) {
			newlog = generalize(16);
			newlog = generalize(17);
		}
		else if(logType.equalsIgnoreCase("ipv6")) {
			newlog = generalize(9);
			newlog = generalize(10);
		}
		else if(logType.equalsIgnoreCase("netflow")) {
			newlog = generalize(6);
			newlog = generalize(7);
		}
	}
	
	//Rounds a port number to nearest hundred if the port number is above 49151.
	public ArrayList<List<String>> generalize(int portFieldNr) {
		ArrayList<List<String>> newLog = new ArrayList<List<String>>();
		for(List<String> pkt : newlog) {
			if(!pkt.get(portFieldNr).contains(".")) {
				if(Integer.parseInt(pkt.get(portFieldNr)) > 49151) {
					List<String> newpkt = new ArrayList<String>();
					for(int i = 0; i < portFieldNr;i++) {
						newpkt.add(pkt.get(i));
					}
					newpkt.add(Integer.toString(Rounding(pkt.get(portFieldNr))));
					for(int i = portFieldNr + 1; i < pkt.size(); i++) {
						newpkt.add(pkt.get(i));
					}
					newLog.add(newpkt);
				}
				else {
					newLog.add(pkt);
				}
			}
			else {
				newLog.add(pkt);
			}
		}
		return newLog;
	}
	
	//Performs the actual rounding.
	public int Rounding(String port) {
		return (int)(Math.round(Integer.parseInt(port)/100.0) * 100);
	}
	
	//Method to write lines from the new log to file.
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
				bw.write(line);
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
	
	
	public static void main(String[] args) throws FileNotFoundException {
		if (args.length !=3) {
		      System.err.println("usage: java -jar jarfile.jar logtype originalInput.dat anonymizedInput.dat \n"
		    		  + "The logtype must be either IPv4, IPv6 or Netflow");
		      System.exit(-1);
		    }
		else {
			Generalization rs = new Generalization(args[0],args[1],args[2]);
		}
	}
}
