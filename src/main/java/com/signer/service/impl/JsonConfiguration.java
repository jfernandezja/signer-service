package com.signer.service.impl;

import java.io.File;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.io.FileUtils;
import org.json.JSONObject;

import com.signer.service.Configuration;

public class JsonConfiguration implements Configuration {
	private static final String CONFIG_FILE = "config.json";
	private static final String PORT_PARAM = "port";
	private static final String JWS_KEY_PARAM = "jws_public_key";

	private int port;
	private RSAPublicKey jwsKey;

	public JsonConfiguration(String config) throws Exception {
		initialize(config);
	}

	public JsonConfiguration() throws Exception {
		byte[] config = FileUtils.readFileToByteArray(new File(CONFIG_FILE));
		initialize(new String(config));
	}


	public int getPort() {
		return port;
	}
	
	public RSAPublicKey getJwsKey() {
		return jwsKey;
	}

	private void initialize(String config) throws Exception {
		JSONObject obj = new JSONObject(config);
		initPort(obj);
		initJwsKey(obj);
	}

	private void initPort(JSONObject obj) throws Exception {

		port = obj.getInt(PORT_PARAM);
	}

	private void initJwsKey(JSONObject obj) throws Exception {
		String pvk = obj.getString(JWS_KEY_PARAM);
		byte[] encoded = Base64.getDecoder().decode(pvk.getBytes());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		jwsKey = (RSAPublicKey)kf.generatePublic(spec);

	}
}
