package src;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;




public class Main {

	private static SecretKey keyTest ;
	private static boolean a ;
	private static int compteur;
	private static SecretKey keyFound ;
	private static int falseAlarm;
	
	
	public static void main(String[] args) throws Exception {
		int t= 10; // specify here the value of t.
		int m=10000; // specify here the value of m.
		a = true;
		compteur = 0;
		falseAlarm = 0;
		
		
		String ss = "Hello world"; // the plaint text
		byte[] plainText = ss.getBytes();
		byte[] cipherText;
		
		 
		keyTest = getRandomKey();
		
		// this is the exaustive search of the key: uncomment to use it
//		cipherText = encrypte(keyTest,plainText);
//		Long timee0 = System.currentTimeMillis();
//		SecretKey key = exaustive(cipherText,plainText);
//		Long timee1 = System.currentTimeMillis();
//		System.out.println("exution time  ::"+((timee1-timee0)/1000.) + "seconde");
//		

		
		// this is using Distpoints : 
		cipherText = encrypte(keyTest,plainText);
		Long time0 = System.currentTimeMillis();
		//hellman
		ArrayList<StartEndPoint> l = offlineHellman(plainText,t,m);
		//dispoints : uncomment to use it
		//ArrayList<StartEndPoint> l = offlineDistPoints(plainText,t,m);
		
		Long time1 =  System.currentTimeMillis();
		//hellman
		onlineHellman(l,cipherText,plainText,t);
		
		//dispoints : uncomment to use it
		//onlineDistPoints(l,cipherText,plainText,t);
		
		
		Long time2 = System.currentTimeMillis();

		
		System.out.println("exution time offline ::"+((time1-time0)/1000.) + "seconde");
		System.out.println("exution time online ::"+((time2-time1)/1000.) + "seconde");
		System.out.println("number of false alarm :: "+falseAlarm);

	}

	
	
	

	static byte [] next_bytes(byte [] key, int taille){
		for(int i=taille-1;i>=0;i--){
			if(key[i]!=127) break;
			if(i==0)return null;
		}
		for(int i=taille-1;i>=0;i--){
			int temp = key[i];
			if(temp+1<=127){
				key[i]++;
				break;
			}else{
				key[i]++;
			}
			
		}
		return key;
	}


	public static SecretKey exaustive(byte [] cipherText,byte [] plainText) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchPaddingException, InterruptedException{
		byte [] key0 = {-128,-128,-128,-128};
		SecretKey key1;
		while (key0 != null){
			byte [] key = {-1,-1,-1,-1,key0[3],key0[2],key0[1],key0[0]};
			//System.out.println(Arrays.toString(key));
			key1 = genSpecKey(key);
			byte [] cipher = encrypte(key1,plainText);
			if(Arrays.equals(cipher,cipherText)){
				System.out.println("key :"+Arrays.toString(key1.getEncoded()));
				return key1;
			}
			key0 = next_bytes(key0,4);
		}
		return null;
	}


	
	/**
	 * 
	 * @param SE
	 * @param cipherText
	 * @param plainText
	 * @param t the number of itteration t .
	 * @return true if found the key
	 * 
	 */
	public static boolean onlineHellman(ArrayList<StartEndPoint> SE,byte[] cipherText,byte [] plainText, int t) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException{

		System.out.println("Start onlineHellman");
		for (int i = 0;i<SE.size();i++){
			if( Arrays.equals(SE.get(i).getEp(),reduction(cipherText))){
				byte[] cipher = f(SE.get(i).getSp(),plainText,t-1);
				SecretKey condidateKey = genSpecKey(cipher);
				//System.out.println("online find 3");
				byte[] cipherC = encrypte(condidateKey,plainText) ;

				if (Arrays.equals (cipherC,cipherText) ){
					System.out.println("Found the Key :"+ Arrays.toString(condidateKey.getEncoded()));
					System.out.println("The Real   key"+ Arrays.toString(keyTest.getEncoded()));
					keyFound = condidateKey;
					return true;
					//return condidateKey;
				}else{

					System.out.println("the false cipher : "+ Arrays.toString(cipherC));
					System.out.println("the real cipher : "+ Arrays.toString(cipherText));
					System.out.println("False alarme type1");
					falseAlarm++;
					//return null;
					//Thread.sleep(4000);
				}
			}	
			byte[] cipher0 = cipherText;
			byte[] redC0 = reduction(cipher0);
			SecretKey key0 = genSpecKey(redC0);
			//for (int j = 0; j < SE.size(); j++){
			SecretKey key = key0;
			for(int e=0 ; e<t-1 ; e++){
				byte[] cipher2 = encrypte(key,plainText);

				for (int j = 0; j < SE.size(); j++){
					if(Arrays.equals(reduction(cipher2), SE.get(j).getEp())){
						byte[] cipherCondidate = f(SE.get(j).getSp(),plainText,t-(e+2));
						SecretKey keyCondidate = genSpecKey(cipherCondidate);
						byte[] C2 = encrypte(keyCondidate,plainText);
						System.out.println("condidate");

						if (Arrays.equals( C2 , cipherText )){
							System.out.println("Found the key"+ Arrays.toString(keyCondidate.getEncoded()));
							System.out.println("the  key"+ Arrays.toString(keyTest.getEncoded()));
							keyFound = keyCondidate;
							//return keyCondidate;
							return true;
						}else{
							//tests : 
							//the real end point
							//							System.out.println("e::" +e+ "the real end point : "+ Arrays.toString(SE.get(j).getEp()));
							//							System.out.println("the  cipher2 : "+ Arrays.toString(reduction(cipher2)));
							//							//the false cipher
							//							System.out.println("the false cipher we obtain : "+ Arrays.toString(C2));
							//							//the real cipher
							//							System.out.println("the real cipher : "+ Arrays.toString(cipherText));
							//							//verification si on a récupérer la bonne clé
							//							System.out.println("verifiying the end point using the key we found  ::"+Arrays.toString(f(keyCondidate,plainText,(e+2))));
							//							
							//							//verification si le cipher donne le meme end point
							//							System.out.println("the end point with ciphertext to confirm that is due to collision ::"+Arrays.toString(f(key0,plainText,(e+1))));
							//							//tests to notice that we have the same end points using different keys
							System.out.println("False alarme type 2");
							falseAlarm++;
							//Thread.sleep(5000);
						}
					}
				}
				key = genSpecKey(reduction (cipher2));
				//cipher = cipher2;
			}
		}



		System.out.println("End onlineHellman");
		System.out.println("key not found");
		//return null;
		return false;

	}


	public static ArrayList<StartEndPoint> offlineHellman(byte[] plainText, int t,int m) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchPaddingException, InterruptedException{
		System.out.println("Start offlineHellman");
		ArrayList<StartEndPoint> startEndPoint = new ArrayList<StartEndPoint>(); 

		for (int j=1 ; j<m+1 ; j++){

			SecretKey Sp1 = getRandomKey();
			///  used just for testing if the algorithm is working 
			//			if (j == 1){
			//			byte [] c = {1,1,1,1,1,1,1,1};
			//			Sp1 = new SecretKeySpec(c,0,c.length,"DES");
			//			}//////
			//			if(j==1){
			//				Sp1 = keyTest; 
			//			}
			SecretKey key = Sp1;
			byte [] Ep1 = f(key,plainText,t);


			StartEndPoint s = new StartEndPoint(Sp1,Ep1);
			startEndPoint.add(s);
			//			compteur++;
		}

		System.out.println("End offlineHellman");
		return startEndPoint;

	}
	public static SecretKey onlineDistPoints(ArrayList<StartEndPoint> SE,byte[] cipherText,byte [] plainText, int t) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException{

		System.out.println("Start onlineDistPoints");
		byte [] reducedCipher = reduction(cipherText); 
		// test with the pattern
		if (reducedCipher[4]==0 && reducedCipher[5] == 0){
			for (int i = 0;i<SE.size();i++){
				if( Arrays.equals(SE.get(i).getEp(),reduction(cipherText))){

					System.out.println("online find ");
					byte[] cipher = f(SE.get(i).getSp(),plainText,t-1);
					SecretKey condidateKey = genSpecKey(cipher);
					//System.out.println("online find 3");
					byte[] cipherC = encrypte(condidateKey,plainText) ;

					if (Arrays.equals (cipherC,cipherText) ){
						System.out.println("Found the Key :"+ Arrays.toString(condidateKey.getEncoded()));
						System.out.println("The Real   key"+ Arrays.toString(keyTest.getEncoded()));
						return condidateKey;
					}else{

						//System.out.println("the false cipher : "+ Arrays.toString(cipherC));
						//System.out.println("the real cipher : "+ Arrays.toString(cipherText));
						System.out.println("False alarme type 1");
						falseAlarm++;
						//return null;
						//Thread.sleep(10000);
					}
				}
			}
		}
			byte[] cipher0 = cipherText;
			byte[] redC0 = reduction(cipher0);
			SecretKey key0 = genSpecKey(redC0);
			SecretKey key = key0;
			for(int e=0 ; e<t-1 ; e++){
				byte[] cipher2 = encrypte(key,plainText);
				byte[] reducedCipher2 = reduction(cipher2);
				// here to test the pattern
				if (reducedCipher2[4] == 0 && reducedCipher2[5] == 0){

					for (int j = 0; j < SE.size(); j++){
						if(Arrays.equals(reduction(cipher2), SE.get(j).getEp())){
							byte[] cipherCondidate = f(SE.get(j).getSp(),plainText,t-(e+2));

							SecretKey keyCondidate = genSpecKey(cipherCondidate);

							byte[] C2 = encrypte(keyCondidate,plainText);
							System.out.println("condidate");

							if (Arrays.equals( C2 , cipherText )){
								System.out.println("Found the key"+ Arrays.toString(keyCondidate.getEncoded()));
								System.out.println("the  key"+ Arrays.toString(keyTest.getEncoded()));
								return key;
							}else{


								//								//tests : 
								//								//the real end point
								//								System.out.println("e::" +e+ "the real end point : "+ Arrays.toString(SE.get(j).getEp()));
								//								System.out.println("the  cipher2 : "+ Arrays.toString(reduction(cipher2)));
								//								//the false cipher
								//								System.out.println("the false cipher we obtain : "+ Arrays.toString(C2));
								//								//the real cipher
								//								System.out.println("the real cipher : "+ Arrays.toString(cipherText));
								//								//verification si on a récupérer la bonne clé
								//								System.out.println("verifiying the end point using the key we found  ::"+Arrays.toString(f(keyCondidate,plainText,(e+2))));
								//
								//								//verification si le cipher donne le meme end point
								//								System.out.println("the end point with ciphertext to confirm that is due to collision ::"+Arrays.toString(f(key0,plainText,(e+1))));
								//								//tests to notice that we have the same end points using different keys
								System.out.println("False alarme type 2");
								falseAlarm++;

							}
						}
					}
				}
				key = genSpecKey(reduction (cipher2));
				//cipher = cipher2;
			}
		



		System.out.println("End onlineDistPoints");
		System.out.println("key not found");
		return null;

	}



	public static ArrayList<StartEndPoint> offlineDistPoints(byte[] plainText, int t,int m) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchPaddingException, InterruptedException{
		System.out.println("Start offlineDisPoints");
		ArrayList<StartEndPoint> startEndPoint = new ArrayList<StartEndPoint>(); 

		for (int j=1 ; j<m+1 ; j++){

			SecretKey Sp1 = getRandomKey();
			///  used just for testing if the algorithm is working 
			//			if (j == 1){
			//			byte [] c = {1,1,1,1,1,1,1,1};
			//			Sp1 = new SecretKeySpec(c,0,c.length,"DES");
			//			}//////
			//			if(j==1){
			//				Sp1 = keyTest; 
			//			}
			SecretKey key = Sp1;
			byte [] Ep1 = fDisPoints(key,plainText,t);

			// keep just the end point with the right pattern:
			if (Ep1 != null){
				StartEndPoint s = new StartEndPoint(Sp1,Ep1);
				startEndPoint.add(s);
			}

			//			compteur++;
		}

		System.out.println("End offlineDisPoints");
		return startEndPoint;

	}

	
	// the funtion f for the dispoints , stops if we have the pattern, or till t.
	public static byte[] fDisPoints(SecretKey key,byte[] plainText, int t) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException{
		byte[] cipher = null;
		if (t==0){
			cipher = key.getEncoded();
		}
		for (int i = 1; i < t+1; i++){


			byte[] cipherText = encrypte(key,plainText);

			// used for testing the algorithm : 
			//			if(i == 8 && a == true && compteur == 5){
			//				System.out.println("dans f : " + Arrays.toString(key.getEncoded()));
			//				keyTest = key;
			//				
			//				System.out.println("Dans la fonction f :::"+Arrays.toString(reduction(cipherText)));
			//				System.out.println("i ::" +i+"   t+1 ::" +(t+1));
			//				a = false;
			//				
			//			}
			cipher = reduction(cipherText);
			//the pattern : deux octets des 32 octects = 0
			if(cipher[4]==0 && cipher[5] == 0 ){
				return cipher;
			}
			key = genSpecKey(cipher);
		}
		// keep  just chains with right pattern
		return null;
	}


	public static byte[] f(SecretKey key,byte[] plainText, int t) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException{
		byte[] cipher = null;
		if (t==0){
			cipher = key.getEncoded();
		}
		for (int i = 1; i < t+1; i++){


			byte[] cipherText = encrypte(key,plainText);

			// used for testing the algorithm : 
			//			if(i == 8 && a == true && compteur == 5){
			//				System.out.println("dans f : " + Arrays.toString(key.getEncoded()));
			//				keyTest = key;
			//				
			//				System.out.println("Dans la fonction f :::"+Arrays.toString(reduction(cipherText)));
			//				System.out.println("i ::" +i+"   t+1 ::" +(t+1));
			//				a = false;
			//				
			//			}


			cipher = reduction(cipherText);
			key = genSpecKey(cipher);
		}
		return cipher;
	}

	public static byte[] reduction(byte [] b){
		byte[] c = {0,0,0,0,b[b.length-4],b[b.length-3],b[b.length-2],b[b.length-1]};
		//byte[] c = {0,0,0,0,0,b[b.length-3],b[b.length-2],b[b.length-1]};
		//byte[] c = {0,0,0,0,0,0,b[b.length-2],b[b.length-1]};
		return c;	
	}


	public static SecretKey getRandomKey() throws NoSuchAlgorithmException{
		//System.out.println("\nStart generating DES key");
		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		keyGen.init(56);
		Key key = keyGen.generateKey();
		byte[] b = key.getEncoded();
		SecretKey key2 = genSpecKey(b);
		return key2;
	}




	public static SecretKey genSpecKey(byte[] b){	
		byte [] c = b.clone(); 
		c[0]=(byte) -1;
		c[1]=(byte) -1;
		c[2]=(byte) -1;
		c[3]=(byte) -1;
	//	c[4]=(byte) -1;
	//	c[5]=(byte) -1;
		//c[6]=(byte) -1;
		SecretKey key2 = new SecretKeySpec(c,0,c.length,"DES");
		//System.out.println("Finish generating DES key");
		return key2; 
	}


	public static byte[] encrypte(Key key2, byte[] plainText ) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException{
		//
		// get a DES cipher object and print the provider
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		// encrypt using the key and the plaintext
		//System.out.println("\nStart encryption");
		cipher.init(Cipher.ENCRYPT_MODE, key2);
		byte[] cipherText = cipher.doFinal(plainText);
		//System.out.println("Finish encryption: ");
		//System.out.println(new String(cipherText, "UTF8"));
		return cipherText;
		//
	}
	public  static byte[] decrypte(Key key2 , byte[] cipherText) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException{
		//
		// get a DES cipher object and print the provider
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		// decrypt the ciphertext using the same key
		//System.out.println("\nStart decryption");
		cipher.init(Cipher.DECRYPT_MODE, key2);
		byte[] newPlainText = cipher.doFinal(cipherText);
		//System.out.println("Finish decryption: ");
		return newPlainText;

	}
	public static int convertToInteger(byte[] b){    
		int MASK = 0xFF;
		int result = 0;   
		result = b[0] & MASK;
		result = result + ((b[1] & MASK) << 8);
		result = result + ((b[2] & MASK) << 16);
		result = result + ((b[3] & MASK) << 24);            
		return result;
	}
	public static SecretKey getNextKey(SecretKey key){
		byte[]  k = key.getEncoded();
		//		if(k[7] <127 ){
		//			k[7]++;
		//		}else{
		//			if(k[7]  == 127){
		//				k[7]=-1;
		//				if(k[6]<127){
		//					k[6]++;
		//				}else{
		//					if(k[6] == 127){
		//						k[6] = -1;
		//						if(k[5] <)
		//					}
		//				}
		//			}
		//		}
		//		
		return genSpecKey(k);
	}

}