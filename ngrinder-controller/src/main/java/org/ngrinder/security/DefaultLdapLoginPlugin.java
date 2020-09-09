package org.ngrinder.security;

import com.unboundid.ldap.sdk.*;
import lombok.RequiredArgsConstructor;
import org.ngrinder.extension.OnLoginRunnable;
import org.ngrinder.model.Role;
import org.ngrinder.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang.StringUtils.EMPTY;
import static org.apache.commons.lang.StringUtils.isBlank;

@Component
@RequiredArgsConstructor
public class DefaultLdapLoginPlugin implements OnLoginRunnable {
	private static final Logger log = LoggerFactory.getLogger(DefaultLdapLoginPlugin.class);

	private final NGrinderLdapContext ldapContext;

	@Override
	public User loadUser(String userId) {
		if (!ldapContext.isEnabled()) {
			return null;
		}

		Entry userEntry = getUserFromLDAP(userId);
		if (userEntry == null) {
			return null;
		}

		User user = new User();
		user.setUserId(userId);
		user.setUserName(userEntry.getAttribute(ldapContext.getUserNameKey()).getValue());
		user.setEmail(userEntry.getAttribute(ldapContext.getUserEmailKey()).getValue());
		user.setAuthProviderClass(this.getClass().getName());
		user.setEnabled(true);
		user.setExternal(true);
		user.setRole(Role.USER);
		return user;
	}

	private Entry getUserFromLDAP(String userId) {
		try {
			String searchBase = normalizeUserSearchBase(ldapContext.getBaseDN(), ldapContext.getUserSearchBase());
			String searchFilter = normalizeUserSearchFilter(ldapContext.getUserFilter(), userId);

			SearchRequest request = new SearchRequest(searchBase, SearchScope.ONE, searchFilter);
			SearchResult result = ldapContext.getLdapConnection().search(request);
			if (result == null) {
				return null;
			}
			if (result.getEntryCount() > 0) {
				return result.getSearchEntries().get(0);
			}
		} catch (LDAPException e) {
			log.error("Cannot find {} in LDAP, ", userId, e);
		}
		return null;
	}

	private String normalizeUserSearchFilter(String userFilter, String userId) {
		if (!userFilter.startsWith("(") || !userFilter.endsWith(")")) {
			userFilter = "(" + userFilter + ")";
		}
		String userIdFilter = String.format("(CN=%s)", userId);

		if (isBlank(userFilter) && isBlank(userId)) {
			return EMPTY;
		}

		if (isBlank(userFilter)) {
			return userIdFilter;
		}

		if (isBlank(userId)) {
			return userFilter;
		}

		return String.format("(&%s%s)", userFilter, userIdFilter);
	}

	private String normalizeUserSearchBase(String baseDN, String userSearchBase) {
		if (isBlank(baseDN) && isBlank(userSearchBase)) {
			return EMPTY;
		}

		if (isBlank(baseDN)) {
			return userSearchBase;
		}

		if (isBlank(userSearchBase)) {
			return baseDN;
		}

		return userSearchBase.trim() + "," + baseDN.trim();
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
