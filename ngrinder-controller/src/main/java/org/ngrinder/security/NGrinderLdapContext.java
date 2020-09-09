package org.ngrinder.security;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.ngrinder.common.exception.NGrinderRuntimeException;
import org.ngrinder.common.util.PropertiesWrapper;
import org.ngrinder.infra.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.ngrinder.common.constant.LdapConstants.*;

@Component
@RequiredArgsConstructor
public class NGrinderLdapContext {
	private static final Logger log = LoggerFactory.getLogger(NGrinderLdapContext.class);

	private final ApplicationContext applicationContext;
	private final Config config;

	@Getter
	private LDAPConnection ldapConnection;

	@PostConstruct
	public void init() {
		config.addSystemConfListener(event -> initialize());
		initialize();
	}

	private void initialize() {
		ldapConnection = createLdapConnection();

		if (ldapConnection != null) {
			log.info("LDAP login is enabled");
			applicationContext.getAutowireCapableBeanFactory().autowireBean(DefaultLdapLoginPlugin.class);
		}
	}

	private LDAPConnection createLdapConnection() {
		if (!isEnabled()) {
			log.info("LDAP login is disabled");
			return null;
		}

		PropertiesWrapper properties = config.getLdapProperties();

		String ldapServer = properties.getProperty(PROP_LDAP_SERVER, "").replace("ldap://", "");
		if (isEmpty(ldapServer)) {
			log.info("LDAP server is not specified. LDAP login is disabled");
			return null;
		}

		int ldapPort = properties.getPropertyInt(PROP_LDAP_PORT);
		String managerDn = properties.getProperty(PROP_LDAP_MANAGER_DN);
		String managerPassword = properties.getProperty(PROP_LDAP_MANAGER_PASSWORD);

		LDAPConnectionOptions ldapConnectionOptions = new LDAPConnectionOptions();
		ldapConnectionOptions.setResponseTimeoutMillis(properties.getPropertyInt(PROP_LDAP_RESPONSE_TIMEOUT));

		try {
			if (isNotEmpty(managerDn) && isNotEmpty(managerPassword)) {
				return new LDAPConnection(ldapConnectionOptions, ldapServer, ldapPort, managerDn, managerPassword);
			} else {
				return new LDAPConnection(ldapConnectionOptions, ldapServer, ldapPort);
			}
		} catch (Exception e) {
			throw new NGrinderRuntimeException(e);
		}
	}

	public boolean isEnabled() {
		return config.getLdapProperties().getPropertyBoolean(PROP_LDAP_ENABLED, false);
	}

	public String getUserNameKey() {
		return config.getLdapProperties().getProperty(PROP_LDAP_USER_DISPLAY_NAME);
	}

	public String getUserEmailKey() {
		return config.getLdapProperties().getProperty(PROP_LDAP_USER_EMAIL);
	}

	public String getBaseDN() {
		return config.getLdapProperties().getProperty(PROP_LDAP_BASE_DN, "");
	}

	public String getUserSearchBase() {
		return config.getLdapProperties().getProperty(PROP_LDAP_USER_SEARCH_BASE, "");
	}

	public String getUserFilter() {
		return config.getLdapProperties().getProperty(PROP_LDAP_USER_SEARCH_FILTER);
	}
}
