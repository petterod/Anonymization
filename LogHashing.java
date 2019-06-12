package anonymisering;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class LogHashing {
	
	ArrayList<List<String>> log = new ArrayList<List<String>>();
	ArrayList<String> newlog;
	
	public LogHashing(String logType, String inputFile, String outputFile) throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		Scanner s = new Scanner(new File(inputFile));
		while(s.hasNextLine()) {	
			log.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		
		if(logType.equalsIgnoreCase("syslog")) {
			newlog = syslogHashing();
		}
		else if(logType.equalsIgnoreCase("webserver")) {
			newlog = webserverHashing();
		}
		toTextFile(outputFile);
	}
	
	//Hashes every component of a syslog message after the message has been split on space. Creates a new packet
	//equal to the old one, but adds the hashed message field value.
	public ArrayList<String> syslogHashing() throws NoSuchAlgorithmException, InvalidKeySpecException {
		ArrayList<String> tempLog = new ArrayList<String>();
		PBKDF2 p = new PBKDF2();
		for(List<String> pkt : log) {
			String newPkt = "";
			for(int i = 0; i < pkt.size();i++) {
				if(i==1) {
					newPkt += p.getGenerated(pkt.get(i)) + "\t";
				}
				else if(i==3) {
					if(pkt.get(i).contains(" ") && pkt.get(i).length() > 1) {
						String[] words = pkt.get(i).split(" ");
						for(String word : words) {
							newPkt += p.getGenerated(word) + " ";
						}
						newPkt += "\t";
					}
					else {
						newPkt += p.getGenerated(pkt.get(i)) + "\t";	
					}
				}
				else {
					newPkt += pkt.get(i) + "\t";
				}
			}
			tempLog.add(newPkt);
		}
		return tempLog;
	}
	
	//Builds a new packet equal to the original one with only the URL value hashed. How it is hashed is dictated by
	//checkRequest().
	public ArrayList<String> webserverHashing() throws NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		ArrayList<String> tempLog = new ArrayList<String>();
		for(List<String> pkt : log) {
			String newPkt = "";
			for(int i = 0; i < pkt.size();i++) {
				if(i==5) {
					newPkt += checkRequest(pkt.get(i)) + "\t";
				}
				else {
					newPkt += pkt.get(i) + "\t";
				}
			}
			tempLog.add(newPkt);
		}
		return tempLog;
	}
	
	//Checks are performed to see if the URL is valid or not. If it is empty, or just consists of one character, 
	//the whole request is hashed. Otherwise, URLManipluation is called.
	public String checkRequest(String request) throws NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		if(request.contains(" ") || request.equals("-") || request.length() == 1) {
			PBKDF2 p = new PBKDF2();
			return p.getGenerated(request);
		}
		else {
			try {
				return URLManipulation(request);
			}
			catch (MalformedURLException e) {
				return URLModified("https://a.b" + request);
			}
		}
	}
	
	//This method is used when a malformedURLException is caught, and 'https://a.b' has been added. This addition 
	//makes the URL valid again, while URLManipulation is called without this addition so the URL is equal to the
	//original
	public String URLModified(String request) throws NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		return URLManipulation(request).substring(3);
	}
	
	//Hashes the directories of a URL after a split on '/'. 
	public String directoryManipulation(String request, PBKDF2 object) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String[] tokens = request.split("/");
		String result = "";
		for(String token : tokens) {
			if(!token.isEmpty()) {
				result += "/" + object.getGenerated(token);
			}
		}
		return result;
	}
	
	//Checks how the URL is formatted.
	public String URLManipulation(String request) throws NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		PBKDF2 p = new PBKDF2();
		URL u = new URL(request);
		if(u.getPath()==null && u.getQuery()==null) {
			return u.getAuthority() + "/";
		}
		else if(u.getQuery()==null) {
			return u.getAuthority() + directoryManipulation(u.getPath().substring(1),p);
		}
		else {
			return u.getAuthority() + directoryManipulation(u.getPath().substring(1),p) + "?" + splitQuery(u);
		}
	}
	
	//Method that hashes a URL query after a split on '&' and '=', and returns the hashed value of the splitted query
	//parts. 
	public static String splitQuery(URL url) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
		PBKDF2 j = new PBKDF2();
		final Map<String, List<String>> query_pairs = new LinkedHashMap<String, List<String>>();
		if(url.getQuery().contains("&") && url.getQuery().contains("=")) {
			final String[] pairs = url.getQuery().split("&");
			for (String pair : pairs) {
				final int idx = pair.indexOf("=");
			    final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
			    	if (!query_pairs.containsKey(key)) {
			    		query_pairs.put(key, new LinkedList<String>());
			    	}
			    final String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : null;
			    query_pairs.get(key).add(value);
			}
			String request = "";
			for(String term : query_pairs.keySet()) {
				request += j.getGenerated(term) + "=";
				for(String value : query_pairs.get(term)) {
					if(value != null) {
						request += j.getGenerated(value) + "&";
					}
					else {
						request += "&";
					}
				}
			}
			return request.substring(0,request.length()-1);	
		}
		else {
			return j.getGenerated(url.getQuery());
		}
	}

	//Method to write lines from the new log to file.	  
	public void toTextFile(String FNAME) throws NoSuchAlgorithmException, InvalidKeySpecException {
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) {			
			for (String line : newlog) {
				bw.write(line + "\n");
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
	
	public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		if (args.length !=3) {
		      System.err.println("Usage: java -jar jarfile.jar logType Original.dat Anonymized.dat \n"
		    		  + "The logtype must be either Webserver or Syslog");
		      System.exit(-1);
		    }
		else {
			LogHashing p = new LogHashing(args[0],args[1],args[2]);
		}
	}
}
