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

public class IdentificationGrouping {
	
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<List<String>> newlog;
	
	public IdentificationGrouping(String inputFile, String outputFile) throws FileNotFoundException{
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		newlog = anonymization();
		toTextFile(outputFile);
	}
	
	//Groups Identification values into eight different groups.
	public ArrayList<List<String>> anonymization() {
		ArrayList<List<String>> newLog = new ArrayList<List<String>>();
		for(List<String> pkt : log) {
			List<String> newpkt = new ArrayList<String>();
			for(int j = 0; j < 6;j++) {
				newpkt.add(pkt.get(j));
			}
			if(Integer.parseInt(pkt.get(6)) >= 0 && Integer.parseInt(pkt.get(6)) <= 8191) {
				newpkt.add("8191");
			}
			else if(Integer.parseInt(pkt.get(6)) >= 8192 && Integer.parseInt(pkt.get(6)) <= 16383) {
				newpkt.add("16383");
			}
			else if(Integer.parseInt(pkt.get(6)) >= 16384 && Integer.parseInt(pkt.get(6)) <= 24575) {
				newpkt.add("24575");
			}
			else if(Integer.parseInt(pkt.get(6)) >= 24576 && Integer.parseInt(pkt.get(6)) <= 32767) {
				newpkt.add("32767");
			}
			else if(Integer.parseInt(pkt.get(6)) >= 32768 && Integer.parseInt(pkt.get(6)) <= 40959) {
				newpkt.add("40959");
			}
			else if(Integer.parseInt(pkt.get(6)) >= 40960 && Integer.parseInt(pkt.get(6)) <= 49151) {
				newpkt.add("49151");
			}
			else if(Integer.parseInt(pkt.get(6)) >= 49152 && Integer.parseInt(pkt.get(6)) <= 57343) {
				newpkt.add("57343");
			}
			else {
				newpkt.add("65535");
			}
			for(int j = 7; j < pkt.size(); j++) {
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
		if (args.length !=2) {
		      System.err.println("usage: java -jar jarfile.jar originalInput.dat anonymizedInput.dat \n");
		      System.exit(-1);
		    }
		else {
			IdentificationGrouping rs = new IdentificationGrouping(args[0],args[1]);
		}
	}
}
