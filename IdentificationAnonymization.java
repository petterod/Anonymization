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

public class IdentificationAnonymization {
	
	HashMap<Integer,Integer> mapping = new HashMap<Integer,Integer>();
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<List<String>> newlog;
	
	public IdentificationAnonymization(String inputFile, String outputFile) throws FileNotFoundException{
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		newlog = anonymization();
		toTextFile(outputFile);
	}
	
	
	
	public ArrayList<List<String>> anonymization() {
		ArrayList<List<String>> newLog = new ArrayList<List<String>>();
		//mapping.put(1,Integer.parseInt(log.get(0).get(6)));
		//newLog.add(log.get(0));
		int iterate = 1;
		for(int i = 0; i < log.size();i++) {
			System.out.println(log.get(i).get(6));
			int addValue = 0;
			boolean breakRegistered = false;
			for(Integer map : mapping.keySet()) {
				if(Math.abs(mapping.get(map) - Integer.parseInt(log.get(i).get(6))) <= 256) {
					//System.out.println("mapped");
					addValue = map;
					breakRegistered = true;
					break;					
				}
			}
			if(!breakRegistered) {
				addValue = iterate;
				//System.out.println("not mapped");
				iterate ++;
			}
			mapping.put(addValue, Integer.parseInt(log.get(i).get(6)));
			
			List<String> newpkt = new ArrayList<String>();
			for(int j = 0; j < 6;j++) {
				newpkt.add(log.get(i).get(j));
			}
			newpkt.add(Integer.toString(addValue));
			for(int j = 7; j < log.get(i).size(); j++) {
				newpkt.add(log.get(i).get(j));
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
		IdentificationAnonymization g = new IdentificationAnonymization(
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\O-IPv4.dat",
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\A-Identification-IPv4.dat");
//		if (args.length !=2) {
//		      System.err.println("usage: java -jar jarfile.jar originalInput.dat anonymizedInput.dat \n";
//		      System.exit(-1);
//		    }
//		else {
//			Generalization rs = new Generalization(args[0],args[1]);
//		}
	}
}
