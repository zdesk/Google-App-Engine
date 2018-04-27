package com.jdriven.stateless.security;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;

public class TokenModel implements Serializable{

	private String username;
	private Long id;
	private Long expire;
	private Set<UserRole> roles;
	private Long iat;
	private Long exp;
	private String providerId;
	private String providerUserId;
    
    
    public Long getExpire() {
		return expire;
	}

	public void setExpire(Long expire) {
		this.expire = expire;
	}

	public String getProviderId() {
		return providerId;
	}

	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}

	public String getProviderUserId() {
		return providerUserId;
	}

	public void setProviderUserId(String providerUserId) {
		this.providerUserId = providerUserId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Set<UserRole> getRoles() {
		return roles;
	}

	public void setRoles(Set<UserRole> roles) {
		this.roles = roles;
	}

	public Long getIat() {
		return iat;
	}

	public void setIat(Long iat) {
		this.iat = iat;
	}

	public Long getExp() {
		return exp;
	}

	public void setExp(Long exp) {
		this.exp = exp;
	}

	public static TokenModel getTokenModel( User user) {
    	TokenModel tm = new TokenModel();
    	tm.id = user.getId();
    	tm.username = user.getUsername();
    	tm.expire = user.getExpires();    	
    	tm.roles = user.getRoles();
    	tm.providerUserId = user.getProviderUserId();
    	tm.providerId = user.getProviderId();
    	tm.iat = new Date(System.currentTimeMillis()).getTime();
    	tm.exp = generateExpirationDate();
    	return tm;
    }
	
	public static User getUserModel( TokenModel tm) {
    	User user = new User();
    	user.setUsername(tm.username);
    	user.setId(tm.id);
    	user.setExpires(tm.expire);
    	user.setRoles(tm.roles);
    	user.setProviderId(tm.getProviderId());
    	user.setProviderUserId(tm.getProviderUserId());
    	return user;
    }
    
    private static Long generateExpirationDate() {
        return new Date(System.currentTimeMillis() + 60 * 1000).getTime();
    }
    
    
}
