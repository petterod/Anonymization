package anonymisering;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class WindowSizeShifting {
	
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<List<String>> newlog;
	
	public WindowSizeShifting(int shift, String inputFile, String outputFile) throws FileNotFoundException{
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		newlog = anonymization(shift);
		toTextFile(outputFile);
	}
	
	
	
	public ArrayList<List<String>> anonymization(int shift) {
		ArrayList<List<String>> newLog = new ArrayList<List<String>>();
		for(List<String> pkt : log) {
			List<String> newpkt = new ArrayList<String>();
			for(int j = 0; j < 31;j++) {
				newpkt.add(pkt.get(j));
			}
			int shifted = Integer.parseInt(pkt.get(31)) + shift;
			if(shifted > 65535) {
				newpkt.add("65535");
			}
			else if(shifted < 1) {
				newpkt.add("1");
			}
			else {
				newpkt.add(Integer.toString(shifted));
			}
			
			for(int j = 32; j < pkt.size(); j++) {
				newpkt.add(pkt.get(j));
			}
			newLog.add(newpkt);
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
		WindowSizeShifting g = new WindowSizeShifting(5,
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\O-IPv4.dat",
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\A-WindowSize-IPv4.dat");
//		if (args.length !=2) {
//		      System.err.println("usage: java -jar jarfile.jar originalInput.dat anonymizedInput.dat \n";
//		      System.exit(-1);
//		    }
//		else {
//			Generalization rs = new Generalization(args[0],args[1]);
//		}
	}
}
