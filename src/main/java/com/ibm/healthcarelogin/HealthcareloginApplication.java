package com.ibm.healthcarelogin;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
//Enables Spring Boot’s auto-configuration mechanism, package scan, and registering extra beans in the
//context or import additional configuration classes
@EnableOAuth2Sso //Enables OAuth2 Single Sign On, will automatically use application.yml properties for security
@RestController //Enabling REST functionality. With this, we can now expose our own endpoints
public class HealthcareloginApplication extends WebSecurityConfigurerAdapter 
{

	public static void main(String[] args) {
		SpringApplication.run(HealthcareloginApplication.class, args);
	}
    
	@Override
    protected void configure(HttpSecurity http) throws Exception {
 
        //Configuring Spring security access. For /login, /user, and /userinfo, we need authentication.
        //Logout is enabled.
        //Adding csrf token support to this configurer.
        http.authorizeRequests().antMatchers("/login**", "/user","/userInfo").authenticated();
        http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/").clearAuthentication(true)
        .and().logout().invalidateHttpSession(true).deleteCookies("JSESSIONID").deleteCookies("IBM_WAC_ANONYMOUS_USER_ID")
        .deleteCookies("XSRF-TOKEN");
        
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
 
    }
	@RequestMapping("/user")
    public Principal user(Principal principal) {
        //Principal holds the logged in user information.
        // Spring automatically populates this principal object after login.
        return principal;
    }
 
    @RequestMapping("/userInfo")
    public String userInfo(Principal principal){
        final OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
        final Authentication authentication = oAuth2Authentication.getUserAuthentication();
        //Manually getting the details from the authentication, and returning them as String.
        return authentication.getDetails().toString();
    }
    
}
