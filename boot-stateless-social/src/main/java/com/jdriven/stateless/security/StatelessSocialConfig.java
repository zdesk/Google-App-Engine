package com.jdriven.stateless.security;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.env.Environment;
import org.springframework.social.UserIdSource;
import org.springframework.social.config.annotation.ConnectionFactoryConfigurer;
import org.springframework.social.config.annotation.EnableSocial;
import org.springframework.social.config.annotation.SocialConfigurerAdapter;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.ConnectionRepository;
import org.springframework.social.connect.ConnectionSignUp;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.social.facebook.connect.FacebookConnectionFactory;
import org.springframework.social.google.api.Google;
import org.springframework.social.google.connect.GoogleConnectionFactory;

@Configuration
@EnableSocial
public class StatelessSocialConfig extends SocialConfigurerAdapter {

	@PostConstruct
	private void init() {
	    try {
	        String[] fieldsToMap = {
	            "id", "picture", "about", "age_range", "birthday", "context", "cover", "currency", "devices", 
	            "education", "email", "favorite_athletes", "favorite_teams", "first_name", "gender", "hometown", 
	            "inspirational_people", "installed", "install_type","is_verified", "languages", "last_name", "link", "locale", 
	            "location", "meeting_for", "middle_name", "name", "name_format","political", "quotes", "payment_pricepoints", 
	            "relationship_status", "religion", "security_settings", "significant_other","sports", "test_group", "timezone", 
	            "third_party_id", "updated_time", "verified", "viewer_can_send_gift","website", "work"
	        };

	        Field field = Class.forName("org.springframework.social.facebook.api.UserOperations").
	                getDeclaredField("PROFILE_FIELDS");
	        field.setAccessible(true);

	        Field modifiers = field.getClass().getDeclaredField("modifiers");
	        modifiers.setAccessible(true);
	        modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
	        field.set(null, fieldsToMap);

	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
	}
	
	@Autowired
	private ConnectionSignUp autoSignUpHandler;

	@Autowired
	private SocialUserService userService;

	@Override
	public void addConnectionFactories(ConnectionFactoryConfigurer cfConfig, Environment env) {
		cfConfig.addConnectionFactory(new FacebookConnectionFactory(
				env.getProperty("facebook.appKey"),
				env.getProperty("facebook.appSecret")));
		
		cfConfig.addConnectionFactory(new GoogleConnectionFactory(
				env.getProperty("google.appKey"),
				env.getProperty("google.appSecret")));
		
	
	}

	@Override
	public UserIdSource getUserIdSource() {
		// retrieve the UserId from the UserAuthentication in the security context
		return new UserAuthenticationUserIdSource();
	}

	@Override
	public UsersConnectionRepository getUsersConnectionRepository(ConnectionFactoryLocator connectionFactoryLocator) {
		SimpleUsersConnectionRepository usersConnectionRepository =
				new SimpleUsersConnectionRepository(userService, connectionFactoryLocator);

		// if no local user record exists yet for a facebook's user id
		// automatically create a User and add it to the database
		usersConnectionRepository.setConnectionSignUp(autoSignUpHandler);

		return usersConnectionRepository;
	}

	@Bean
	@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
	public Facebook facebook(ConnectionRepository repository) {
		Connection<Facebook> connection = repository.findPrimaryConnection(Facebook.class);
		return connection != null ? connection.getApi() : null;
	}
	
	@Bean
	@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
	public Google google(ConnectionRepository repository) {
		Connection<Google> connection = repository.findPrimaryConnection(Google.class);
		return connection != null ? connection.getApi() : null;
	}
}
