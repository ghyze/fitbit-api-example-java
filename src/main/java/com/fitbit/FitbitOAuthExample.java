/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.fitbit;

import com.fitbit.model.Activity;
import com.fitbit.model.LifetimeActivity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Arrays;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
@EnableWebSecurity
public class FitbitOAuthExample extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@Autowired
	@Qualifier("fitbitTemplate")
	OAuth2RestTemplate fitbitOAuthRestTemplate;

	@Value("${fitbit.api.resource.activitiesUri}")
	String fitbitActivitiesUri;

	@RequestMapping("/lifetime-activity")
	public LifetimeActivity lifetimeActivity() {
		LifetimeActivity lifetimeActivity;

		try {
			Activity a = fitbitOAuthRestTemplate.getForObject(fitbitActivitiesUri, Activity.class);
			lifetimeActivity = a.getLifetime().getTotal();
		}
		catch(Exception e) {
			lifetimeActivity = new LifetimeActivity();
		}

		return lifetimeActivity;
	}
	
	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
				.authenticated();
	}

	@Bean
	public AuthorizationCodeResourceDetails fitbit(){
		AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
		details.setClientId("YOUR_CLIENT_ID_HERE");
		details.setClientSecret("YOUR_CLIENT_SECRET_HERE");
		details.setAccessTokenUri("https://api.fitbit.com/oauth2/token");
		details.setUserAuthorizationUri("https://www.fitbit.com/oauth2/authorize");
		details.setTokenName("oauth_token");
		details.setAuthenticationScheme(AuthenticationScheme.header);
		details.setClientAuthenticationScheme(AuthenticationScheme.header);
		details.setScope(Arrays.asList("activity", "heartrate", "location", "nutrition", "profile", "settings", "sleep", "social", "weight"));

		return details;
	}

	@Bean
	public OAuth2RestTemplate fitbitTemplate(){
		return new OAuth2RestTemplate(fitbit(), oauth2ClientContext);
	}

	public static void main(String[] args) {
		SpringApplication.run(FitbitOAuthExample.class, args);
	}

}
