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
	
	
	public ArrayList<String> syslogHashing() throws NoSuchAlgorithmException, InvalidKeySpecException {
		ArrayList<String> tempLog = new ArrayList<String>();
		for(List<String> pkt : log) {
			String newPkt = "";
			for(int i = 0; i < pkt.size();i++) {
				if(i==3) {
					PBKDF2 p = new PBKDF2();
					newPkt += p.getGenerated(pkt.get(i)) + "\t";
				}
				else {
					newPkt += pkt.get(i) + "\t";
				}
			}
			tempLog.add(newPkt);
		}
		return tempLog;
	}
	
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
	
	public String checkRequest(String request) throws NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		if(request.contains(" ") || request.equals("-")) {
			System.out.println("Sentence or - : " + request);
			PBKDF2 p = new PBKDF2();
			return p.getGenerated(request);
		}
		else if(!request.contains("www") || request.indexOf(".",request.indexOf(".")+1) == -1) {
			System.out.println("Directory: " + request);
			return directoryManipulation(request);
		}
		else {
			System.out.println("URL: " + request);
			return URLManipulation(request);
		}
	}
	
	public String directoryManipulation(String request) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String[] tokens = request.split("/");
		PBKDF2 p = new PBKDF2();
		String result = "";
		for(String token : tokens) {
			if(!token.isEmpty()) {
				result += "/" + p.getGenerated(token);
			}
		}
		return result;
	}
	
	public String URLManipulation(String request) throws NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
		PBKDF2 p = new PBKDF2();
		URL u = new URL(request);
		if(u.getPath()==null && u.getQuery()==null) {
			return u.getAuthority() + "/";
		}
		else if(u.getQuery()==null) {
			return u.getAuthority() + "/" + p.getGenerated(u.getPath().substring(1));
		}
		else {
			return u.getAuthority() + "/" + p.getGenerated(u.getPath().substring(1)) + "?" + splitQuery(u);
		}
	}
	
	public static String splitQuery(URL url) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
		PBKDF2 j = new PBKDF2();
		  final Map<String, List<String>> query_pairs = new LinkedHashMap<String, List<String>>();
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
				  request += j.getGenerated(value) + "&";
			  }
		  }
		  return request.substring(0,request.length()-1);
	}
		  
	public void toTextFile(String FNAME) {
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) {			
			for (String line : newlog) {
				//System.out.println(line);
				bw.write(line + "\n");
			}
			//System.out.println("Created file " + FNAME);
			bw.close ();
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
	
	public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, MalformedURLException, UnsupportedEncodingException {
//		LogHashing p = new LogHashing("Syslog",
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Syslog\\O-Syslog.dat",
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Syslog\\A-Syslog.dat");
//		LogHashing p = new LogHashing("Webserver",
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Webserver\\O2-Webserver.dat",
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Webserver\\A2-Webserver.dat");
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
