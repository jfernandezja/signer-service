package com.signer.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.json.JSONObject;

public class KeyPairsService {
	public String generateKeyPair(String jsonRequest) throws Exception {
		JSONObject request = new JSONObject(jsonRequest);
		String algorithm = request.getString("algorithm");
		int size = request.getInt("size");
		
		if(!algorithm.equals("RSA"))
			throw new BadRequestException("Only RSA supported");
		
		if(size != 2048 && size != 4096)
			throw new BadRequestException("RSA key size not supported");
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
		kpg.initialize(size);
		KeyPair kp = kpg.generateKeyPair();
		
		JSONObject ret = new JSONObject();
		ret.put("public_key", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
		ret.put("private_key", Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
		return ret.toString();
	}
}
