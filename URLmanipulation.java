package anonymisering;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Scanner;

public class URLmanipulation {
	
	File file = new File("C:\\Users\\Petter\\Documents\\NTNU\\ÂMaster\\Fordypningsprosjekt\\dictionary.txt");
	private ArrayList<String> words = new ArrayList<String>();
	private String domain; 
	private String[] directories;
	private int iterable=0;
	
	private static Hashtable h = new Hashtable();
	
	
	public URLmanipulation(String url) {
		directories = url.split("/",-1); 
		
		if(url.contains("https://")) {
			domain = url.substring(0,url.indexOf('/',url.indexOf('/')+2)) +"/";
		}
		else {
			domain = url.substring(0,url.indexOf('/')+1);
		}
		for (int i = 0; i < directories.length; i++) {
			if (NotInHashtable(directories[i])) {
				h.put(iterable, directories[i]);
				iterable++;
			}
		}
		System.out.println(h);
	}
	
	public void getArray() {
		for (int i=0;i<directories.length;i++) {
			System.out.println(directories[i]);
		}
	}
	
	public boolean NotInHashtable(String directory) {
		return !h.contains(directory)? true: false;
	}
	
	public String findWord() {
		try {
		    Scanner scanner = new Scanner(file);
		    int lineNum = 0;
		    while (scanner.hasNextLine()) {
		        String line = scanner.nextLine();
		        lineNum++;
		        if(Arrays.asList(directories).contains(line)) { 
		            String newURL = domain + line;
		            return newURL;
		        }
		    }
		} catch(FileNotFoundException e) { 
		    System.out.println("Buhu");
		}
		return null;
	}
	
	public String findTokens(){
		String tokens = null;
		for (int i = 0; i < directories.length; i++) {
			for (int j = 0; j < h.size(); j++) {
				if(h.get(j) == directories[i]) {
					tokens += "/" + j;
				}
			}
			if(NotInHashtable(directories[i])) {
				h.put(iterable, directories[i]);
				tokens += "/" + iterable;
				iterable++;
			}
			
		}
		String URLwTokens = domain + tokens;
		return URLwTokens;
	}
	
	@Override
	public String toString() {
		String string = "Den nye URLen er: " + findTokens();
		return string;
	}
	
	
	
	public static void main(String[] args) {
		URLmanipulation url1 = new URLmanipulation("https://www.vg.no/sport/fotball/i/Rx0Ry2/");
		System.out.println(url1);
		System.out.println("");
		URLmanipulation url2 = new URLmanipulation("https://www.vg.no/sport/fotball/i/xRoP2n/");
		System.out.println(url2);
	}


}
