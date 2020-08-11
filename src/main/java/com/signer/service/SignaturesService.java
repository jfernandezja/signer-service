package com.signer.service;

import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.json.JSONObject;

public class SignaturesService {

	public String sign(String jsonRequest) throws Exception {
		JSONObject request = new JSONObject(jsonRequest);
		String algorithm = request.getString("signature_algorithm");
		String data = request.getString("data");
		String privateKey = request.getString("private_key");
		
		if(!algorithm.equals("SHA256withRSA") &&
			!algorithm.equals("SHA512withRSA") )
			throw new BadRequestException("Signature algorithm not supported");
		
		RSAPrivateKey loadedPvk = loadPrivateKey(privateKey);
		
		Signature sign = Signature.getInstance(algorithm);
		sign.initSign(loadedPvk);
		sign.update(Base64.getDecoder().decode(data.getBytes()));
		JSONObject obj = new JSONObject();
		obj.put( "signature", Base64.getEncoder().encodeToString(sign.sign()));
		return obj.toString();
	}
	
	private RSAPrivateKey loadPrivateKey(String privateKey) throws Exception {
		byte[] encoded = Base64.getDecoder().decode(privateKey.getBytes());
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return (RSAPrivateKey) kf.generatePrivate(keySpec);
	}

}
