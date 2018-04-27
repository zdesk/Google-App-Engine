package com.jdriven.stateless.security;

import javax.servlet.Filter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.social.SocialWebAutoConfiguration;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.CharacterEncodingFilter;

@EnableAutoConfiguration (exclude = { SocialWebAutoConfiguration.class })
@Configuration
@ComponentScan
public class StatelessAuthentication {

	public static void main(String[] args) {
		SpringApplication.run(StatelessAuthentication.class, args);
	}

	@Bean
	public Filter characterEncodingFilter() {
		CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
		characterEncodingFilter.setEncoding("UTF-8");
		characterEncodingFilter.setForceEncoding(true);
		return characterEncodingFilter;
	}
	
	@Bean
	public EmbeddedServletContainerCustomizer containerCustomizer() {

	    return new EmbeddedServletContainerCustomizer() {
	        @Override
	        public void customize(ConfigurableEmbeddedServletContainer container) {

	            ErrorPage error401Page = new ErrorPage(HttpStatus.UNAUTHORIZED,
	                    "/index.html");
	            ErrorPage error403Page = new ErrorPage(HttpStatus.FORBIDDEN,
	                    "/index.html");
	            ErrorPage error404Page = new ErrorPage(HttpStatus.NOT_FOUND,
	                    "/index.html");
	            ErrorPage error500Page = new ErrorPage(
	                    HttpStatus.INTERNAL_SERVER_ERROR, "/index.html");
	            ErrorPage error505Page = new ErrorPage(
	                    HttpStatus.HTTP_VERSION_NOT_SUPPORTED, "/index.html");
	            ErrorPage error506Page = new ErrorPage(
	                    HttpStatus.METHOD_NOT_ALLOWED, "/index.html");
	            container.addErrorPages(error401Page, error403Page, error404Page,
	                    error500Page, error505Page, error506Page);
	        }
	    };
	}
}
