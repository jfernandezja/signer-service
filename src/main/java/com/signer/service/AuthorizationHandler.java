package com.signer.service;

import java.security.interfaces.RSAPublicKey;

import com.signer.jwslib.InvalidJwtSignatureException;
import com.signer.jwslib.JWTVerifier;

public class AuthorizationHandler {
	private JWTVerifier verifier;

	public AuthorizationHandler(RSAPublicKey asPublicKey) throws Exception {
		verifier = new JWTVerifier(asPublicKey);
	}
	
	public boolean authorize(String authHeader) throws Exception {
		if(authHeader == null || !authHeader.startsWith("Bearer"))
			throw new BadRequestException("Bearer authorization not present");
		
		String[] split = authHeader.split(" ");
		if(split.length != 2)
			throw new BadRequestException("Invalid Bearer format");
		try {
			verifier.verify(split[1]);
		} catch(InvalidJwtSignatureException e) {
			return false;
		}
		return true;
	}

}
