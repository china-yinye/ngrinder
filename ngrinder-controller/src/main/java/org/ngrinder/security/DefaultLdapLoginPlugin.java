package org.ngrinder.security;

import lombok.RequiredArgsConstructor;
import org.ngrinder.common.exception.NGrinderRuntimeException;
import org.ngrinder.extension.OnLoginRunnable;
import org.ngrinder.model.Role;
import org.ngrinder.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

@Component
@RequiredArgsConstructor
public class DefaultLdapLoginPlugin implements OnLoginRunnable {
	private static final Logger log = LoggerFactory.getLogger(DefaultLdapLoginPlugin.class);

	private final NGrinderLdapContext ldapContext;

	@Override
	public User loadUser(String userId) {
		Attributes userAttributes = getUserFromLDAP(userId);
		if (userAttributes == null) {
			return null;
		}

		try {
			User user = new User();
			user.setUserId(userId);
			user.setUserName((String) userAttributes.get(ldapContext.getUserNameKey()).get());
			user.setEmail((String) userAttributes.get(ldapContext.getUserEmailKey()).get());
			user.setAuthProviderClass(this.getClass().getName());
			user.setEnabled(true);
			user.setExternal(true);
			user.setRole(Role.USER);
			return user;
		} catch (NamingException e) {
			log.error("Fail to load user by LDAP login plugin", e);
			throw new NGrinderRuntimeException(e);
		}
	}

	private Attributes getUserFromLDAP(String userId) {
		SearchResult searchResult = search(userId);
		if (searchResult == null) {
			return null;
		}
		return searchResult.getAttributes();
	}

	private SearchResult search(String userId) {
		SearchResult searchResult = null;
		try {
			String name = String.format("cn=%s,%s", userId, ldapContext.getUserDN());
			NamingEnumeration<SearchResult> enumeration = ldapContext.getLdapContext().search(name, ldapContext.getUserFilter(), ldapContext.getSearchControls());
			if (enumeration.hasMore()) {
				searchResult = enumeration.next();
			}
		} catch (NamingException e) {
			log.error("Cannot find {} in LDAP, ", userId, e);
		}
		return searchResult;
	}

	@Override
	public boolean validateUser(String userId, String password, String encPass, Object encoder, Object salt) {
		// TODO: validate user with LDAP
		return false;
	}

	@Deprecated
	@Override
	public void saveUser(User user) {
		// do nothing
	}
}
