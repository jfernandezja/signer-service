package com.signer.service;

import org.json.JSONException;
import org.junit.Assert;
import org.junit.Test;

public class KeyPairsServiceTest {

	@Test( expected = BadRequestException.class)
	public void invalidAlgorithmTest() throws Exception {
		String request = "{\n" + 
				"    \"algorithm\" : \"ECC\",\n" + 
				"    \"size\" : 2048\n" + 
				"}";
		KeyPairsService service = new KeyPairsService();
		service.generateKeyPair(request);
	}
	
	@Test( expected = BadRequestException.class)
	public void invalidSizeTest() throws Exception {
		String request = "{\n" + 
				"    \"algorithm\" : \"RSA\",\n" + 
				"    \"size\" : 33\n" + 
				"}";
		KeyPairsService service = new KeyPairsService();
		service.generateKeyPair(request);
	}
	
	@Test( expected = JSONException.class)
	public void emptyRequestTest() throws Exception {
		String request = "{}";
		KeyPairsService service = new KeyPairsService();
		service.generateKeyPair(request);
	}
	
	@Test
	public void generate2048KeyPairTest() throws Exception {
		String request = "{\n" + 
				"    \"algorithm\" : \"RSA\",\n" + 
				"    \"size\" : 2048\n" + 
				"}";
		KeyPairsService service = new KeyPairsService();
		String response = service.generateKeyPair(request);
		Assert.assertTrue(response.contains("public_key"));
		Assert.assertTrue(response.contains("private_key"));
	}
	
	@Test
	public void generate4096KeyPairTest() throws Exception {
		String request = "{\n" + 
				"    \"algorithm\" : \"RSA\",\n" + 
				"    \"size\" : 4096\n" + 
				"}";
		KeyPairsService service = new KeyPairsService();
		String response = service.generateKeyPair(request);
		Assert.assertTrue(response.contains("public_key"));
		Assert.assertTrue(response.contains("private_key"));
	}
	
	
	
	

}
