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

public class BilateralClassification {
	
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<List<String>> newlog;
	
	public BilateralClassification(String fieldType, String inputFile, String outputFile) throws FileNotFoundException{
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		assign(fieldType);
		toTextFile(outputFile);
	}
	
	//Checks if the selected field is TTL or Hop Limit
	public void assign(String fieldType) {
		if(fieldType.equalsIgnoreCase("ttl")) {
			newlog = anonymization(11);
		}
		else if(fieldType.equalsIgnoreCase("hoplimit")) {
			newlog = anonymization(6);
		}
	}
	
	//Classifies either the index field value as 0 or 255 
	public ArrayList<List<String>> anonymization(int index) {
		ArrayList<List<String>> newLog = new ArrayList<List<String>>();
		for(List<String> pkt : log) {
			List<String> newpkt = new ArrayList<String>();
			for(int j = 0; j < index;j++) {
				newpkt.add(pkt.get(j));
			}
			if(Integer.parseInt(pkt.get(index)) < 128) {
				newpkt.add("0");
			}
			else if(Integer.parseInt(pkt.get(index))  > 127) {
				newpkt.add("255");
			}
			
			for(int j = index +1; j < pkt.size(); j++) {
				newpkt.add(pkt.get(j));
			}
			newLog.add(newpkt);
		}
		return newLog;
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
		      System.err.println("usage: java -jar jarfile.jar ttl/hoplimit originalInput.dat anonymizedInput.dat \n");
		      System.exit(-1);
		    }
		else {
			BilateralClassification rs = new BilateralClassification(args[0],args[1],args[2]);
		}
	}
}
