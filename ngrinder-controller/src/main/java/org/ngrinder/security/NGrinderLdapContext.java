package org.ngrinder.security;

import lombok.RequiredArgsConstructor;
import org.ngrinder.common.util.PropertiesWrapper;
import org.ngrinder.infra.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import java.util.Hashtable;

import static org.ngrinder.common.constant.LdapConstants.*;

@Component
@RequiredArgsConstructor
public class NGrinderLdapContext {
	private static final Logger log = LoggerFactory.getLogger(NGrinderLdapContext.class);

	private static final String LDAP_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
	private static final String LDAP_SIMPLE_AUTH = "Simple";


	private final Config config;

	private InitialLdapContext ldapContext;

	@PostConstruct
	public void init() throws NamingException {
		boolean enabled = config.getLdapProperties().getPropertyBoolean(PROP_LDAP_ENABLED, false);
		if (!enabled) {
			log.info("LDAP login is disabled");
			return;
		}

		String serverAddress = config.getLdapProperties().getProperty(PROP_LDAP_SERVER);
		if (serverAddress == null) {
			log.info("LDAP server is not specified. LDAP login is disabled");
			return;
		}

		log.info("LDAP login is enabled");

		// TODO: add ldap login plugin bean

		ldapContext = new InitialLdapContext(getLdapEnvironment(), null);
	}

	private Hashtable<?, ?> getLdapEnvironment() {
		PropertiesWrapper ldapProperties = config.getLdapProperties();
		Hashtable<String, String> env = new Hashtable<>();

		env.put(Context.PROVIDER_URL, ldapProperties.getProperty(PROP_LDAP_SERVER));
		env.put(Context.SECURITY_PRINCIPAL, ldapProperties.getProperty(PROP_LDAP_BASE_DN));
		env.put(Context.SECURITY_CREDENTIALS, ldapProperties.getProperty(PROP_LDAP_PASSWORD));
		env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_FACTORY);
		env.put(Context.SECURITY_AUTHENTICATION, LDAP_SIMPLE_AUTH);

		return env;
	}

}
