package com.signer.service;

import java.security.interfaces.RSAPublicKey;

public interface Configuration {
	public int getPort();
	public RSAPublicKey getJwsKey();
}
