package com.jdriven.stateless.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.social.facebook.api.User;
import org.springframework.social.google.api.Google;
import org.springframework.social.google.api.userinfo.GoogleUserInfo;

@RestController
public class FacebookController {

    @Autowired
    Facebook facebook;
    
    @Autowired
    Google google;

    @RequestMapping(value = "/api/facebook/details", method = RequestMethod.GET)
    public User getFacebookDetails() {
    	String [] fields = { "id", "email", "first_name", "last_name", "picture" };
        return facebook.fetchObject("me", User.class, fields);
    }
    
    @RequestMapping(value = "/api/google/details", method = RequestMethod.GET)
    public GoogleUserInfo getGoogleDetails() {    	
        return google.userOperations().getUserInfo();
    }
}
