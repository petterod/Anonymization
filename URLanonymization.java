package anonymisering;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class URLanonymization {
	
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	
	public URLanonymization(String inputpath) throws FileNotFoundException {
		Scanner s = new Scanner(new File(inputpath));
		while(s.hasNextLine()) {	
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
	}
	
	public void urlManipulation() throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBKDF2 hf;
		String url = "";
		String[] tokens = log.get(0).get(5).split("/");
		for(String token : tokens) {
			System.out.println(token);
			hf = new PBKDF2(token);
			String str = hf.getGenerated(token);
			System.out.println(str);
			url += "/" + str;
		}
		PBKDF2 hf1 = new PBKDF2("heisann");
		hf1.getGenerated("heisann");
		hf1.getGenerated("heisann");
		System.out.println(hf1.getStorage());
//		System.out.println(hf1);
//		String str1 = hf1.getGenerated("heisann");
//		PBKDF2 hf2 = new HashFunction("heisann");
//		String str2 = hf1.getGenerated("heisann");
//		System.out.println(str1 + "\n" + str2);
//		System.out.println("this is url: \n" + url);
	}
	
	public boolean checkIfIP() {
		return true;
		
	}
	
	public boolean checkIfEmail() {
		return true;
	}
	
	public boolean checkIfURL() {
		return true;
	}
	
	public void getLog() {
		for(List<String> pkt : log) {
			System.out.println(pkt.get(5));
		}
	}
	
	public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
		URLanonymization url = new URLanonymization(
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Webserver\\O-Webserver.dat");
		url.urlManipulation();
	}

}
