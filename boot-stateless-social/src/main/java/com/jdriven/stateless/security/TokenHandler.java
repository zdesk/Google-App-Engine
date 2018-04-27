package com.jdriven.stateless.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class TokenHandler {

	private static final String HMAC_ALGO = "HmacSHA256";
	private static final String SEPARATOR = ".";
	private static final String SEPARATOR_SPLITTER = "\\.";

	private final Mac hmac;

	public TokenHandler(byte[] secretKey) {
		try {
			hmac = Mac.getInstance(HMAC_ALGO);
			hmac.init(new SecretKeySpec(secretKey, HMAC_ALGO));
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException("failed to initialize HMAC: " + e.getMessage(), e);
		}
	}

	public User parseUserFromToken(String token) {
		final String[] parts = token.split(SEPARATOR_SPLITTER);
		if (parts.length == 3 && parts[1].length() > 0 && parts[2].length() > 0) {
			try {
				final byte[] userBytes = fromBase64(parts[1]);
				final byte[] hash = fromBase64(parts[2]);

				boolean validHash = Arrays.equals(createHmac(userBytes), hash);
				if (validHash) {
					final User user = TokenModel.getUserModel(fromJSON(userBytes));
					if (new Date().getTime() < user.getExpires()) {
						return user;
					}
				}
			} catch (IllegalArgumentException e) {
				//log tempering attempt here
			}
		}
		return null;
	}

	public String createTokenForUser(User user) throws JSONException {
		byte[] tokenHeader = getHeader(hmac);
		byte[] userBytes = toJSON(TokenModel.getTokenModel(user));
		byte[] hash = createHmac(userBytes);
		final StringBuilder sb = new StringBuilder(170);
		sb.append(toBase64(tokenHeader));
		sb.append(SEPARATOR);
		sb.append(toBase64(userBytes));
		sb.append(SEPARATOR);
		sb.append(toBase64(hash));
		return sb.toString();
	}

	private byte [] getHeader(Mac hmac) throws JSONException {
		if(hmac != null) {
			String algo = hmac.getAlgorithm();
			JSONObject header = new JSONObject();
			header.put("alg", algo);
			header.put("typ", "JWT");
			return header.toString().getBytes();
		}
		
		else {
			return null;
		}
	}
	
	private TokenModel fromJSON(final byte[] userBytes) {
		try {
			return new ObjectMapper().readValue(new ByteArrayInputStream(userBytes), TokenModel.class);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	private byte[] toJSON(TokenModel tm) {
		try {
			return new ObjectMapper().writeValueAsBytes(tm);
		} catch (JsonProcessingException e) {
			throw new IllegalStateException(e);
		}
	}

	private String toBase64(byte[] content) {
		return DatatypeConverter.printBase64Binary(content).replace('+', '-').replace('/', '_').replaceAll("=", "");
	}

	private byte[] fromBase64(String urlsafeBase64) {
		urlsafeBase64 = urlsafeBase64.replace('-', '+').replace('_', '/');
		final int rest = urlsafeBase64.length() % 4;
		if (rest != 0) {
			urlsafeBase64 += rest == 3 ? "=" : "==";
		}
		return DatatypeConverter.parseBase64Binary(urlsafeBase64);
	}

	// synchronized to guard internal hmac object
	private synchronized byte[] createHmac(byte[] content) {
		return hmac.doFinal(content);
	}
}
