package org.sagebionetworks;

import static org.sagebionetworks.repo.model.AuthorizationConstants.BOOTSTRAP_PRINCIPAL.AUTHENTICATED_USERS_GROUP;
import static org.sagebionetworks.repo.model.AuthorizationConstants.BOOTSTRAP_PRINCIPAL.PUBLIC_GROUP;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.sagebionetworks.client.SynapseClient;
import org.sagebionetworks.client.exceptions.SynapseNotFoundException;
import org.sagebionetworks.repo.model.ACCESS_TYPE;
import org.sagebionetworks.repo.model.AccessControlList;
import org.sagebionetworks.repo.model.ResourceAccess;
import org.sagebionetworks.repo.model.auth.LoginRequest;

/*
 * As per PLFM-4258 this will update all ACLs in Synapse, splitting READ into READ and DOWNLOAD
 * 
 * To get the list of ACLs to update we run this on the DB
 * SELECT OWNER_ID FROM ACL where OWNER_TYPE='ENTITY';
 */
public class SynapseACLUpdate {
		
	public static void main(String [] args) throws Exception {
		DateFormat format = new SimpleDateFormat("yyyy-MM-dd.HH:mm:ss");
		String stagingArg = getProperty("STAGING", false);
		boolean staging = StringUtils.isEmpty(stagingArg) || stagingArg.equalsIgnoreCase("true");
		System.out.println(format.format(new Date())+": Running against "+(staging?"STAGING":"PRODUCTION")+" database.");
		SynapseClient synapse = SynapseClientFactory.createSynapseClient(staging);
		String userName = getProperty("SYNAPSE_USERNAME");
		String password = getProperty("SYNAPSE_PASSWORD");
		LoginRequest loginRequest = new LoginRequest();
		loginRequest.setUsername(userName);
		loginRequest.setPassword(password);
		synapse.login(loginRequest);

		// this list is about 16,000 long, small enough to fit into memory
		List<Long> entityIds = new ArrayList<Long>(18000);
		try (
				FileInputStream is = new FileInputStream("/owner_id.txt");
				InputStreamReader isr = new InputStreamReader(is, Charset.forName("UTF-8"));
				BufferedReader br = new BufferedReader(isr);
				) {
			String entityId;
			while ((entityId = br.readLine()) != null) {
				if (entityId.equalsIgnoreCase("OWNER_ID")) {
					continue;
				}
				entityIds.add(Long.parseLong(entityId));
			}
		}


		System.out.println(format.format(new Date())+": There are "+entityIds.size()+" ACLs to process.");

		int numChanged=0;
		List<String> notFound = new ArrayList<String>();
		for (int i=0 ; i<entityIds.size(); i++) {
			Long entityId = entityIds.get(i);
			String stringId = "syn"+entityId;
			try {
				AccessControlList acl = synapse.getACL(stringId);
				boolean changed = transformACL(acl);
				if (changed) {
					synapse.updateACL(acl);
					numChanged++;
				}
			} catch (SynapseNotFoundException e) {
				notFound.add(stringId);
			}
			if (0==(i % 100)) {
				System.out.println(format.format(new Date())+": "+(i+1)+" of "+entityIds.size()+
						". Have changed "+numChanged+" ACLs. "+
						notFound.size()+" ACLs were not found.");
			}
		}

		System.out.println(format.format(new Date())+": Done!  Have changed "+numChanged+" of "+entityIds.size()+" ACLs. "+
				notFound.size()+" ACLs were not found.");

		System.out.println("\nNot Found:\n"+notFound);
	}
	
	/*
	 * Note, this mutates the object passed in
	 * 
	 * @return true iff the passed in object has been changed
	 */
	public static boolean transformACL(AccessControlList dto) {
		boolean aclUpdateRequired=false;
		boolean authenticatedUsersDownloadRequired=false; // set to true if we need to give authenticated users DOWNLOAD access
		ResourceAccess authenticatedUsersEntry=null; // 'points' to authenticated users entry in ACL
		Set<ResourceAccess> updatedRAset = new HashSet<ResourceAccess>();
		for (ResourceAccess ra : dto.getResourceAccess()) {
			long principalId = ra.getPrincipalId();
			Set<ACCESS_TYPE> updatedPermissions = new HashSet<ACCESS_TYPE>(ra.getAccessType());
			ResourceAccess updatedRA = new ResourceAccess();
			updatedRA.setPrincipalId(principalId);
			updatedRA.setAccessType(updatedPermissions);
			if (principalId==PUBLIC_GROUP.getPrincipalId()) {
				if (updatedPermissions.contains(ACCESS_TYPE.READ)) {
					authenticatedUsersDownloadRequired=true;
				}
				// PUBLIC can't have download permission!
				boolean setChanged = updatedPermissions.remove(ACCESS_TYPE.DOWNLOAD);
				aclUpdateRequired = aclUpdateRequired || setChanged;
			} else if (updatedPermissions.contains(ACCESS_TYPE.READ)) {
				boolean setChanged = updatedPermissions.add(ACCESS_TYPE.DOWNLOAD);
				aclUpdateRequired = aclUpdateRequired || setChanged;
			}
			if (principalId==AUTHENTICATED_USERS_GROUP.getPrincipalId()) {
				authenticatedUsersEntry=updatedRA;
			}
			updatedRAset.add(updatedRA);
		}
		if (authenticatedUsersDownloadRequired) {
			if (authenticatedUsersEntry==null) {
				authenticatedUsersEntry = new ResourceAccess();
				authenticatedUsersEntry.setPrincipalId(AUTHENTICATED_USERS_GROUP.getPrincipalId());
				authenticatedUsersEntry.setAccessType(new HashSet<ACCESS_TYPE>());
			} else {
				// can't modify an object in a hash set. Remove it, modify it, and re-add it.
				updatedRAset.remove(authenticatedUsersEntry);
			}
			boolean setChanged = authenticatedUsersEntry.getAccessType().addAll(Arrays.asList(new ACCESS_TYPE[]{ACCESS_TYPE.READ,ACCESS_TYPE.DOWNLOAD}));
			aclUpdateRequired = aclUpdateRequired || setChanged;
			updatedRAset.add(authenticatedUsersEntry);
		}
		if (aclUpdateRequired) {
			dto.setResourceAccess(updatedRAset);
		}		
		return aclUpdateRequired;
	}
	
	private static Properties properties = null;

	public static void initProperties() {
		if (properties!=null) return;
		properties = new Properties();
		InputStream is = null;
		try {
			is = SynapseACLUpdate.class.getClassLoader().getResourceAsStream("global.properties");
			properties.load(is);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (is!=null) try {
				is.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
	
	public static String getProperty(String key) {
		return getProperty(key, true);
	}

	public static String getProperty(String key, boolean required) {
		initProperties();
		String environmentVariable = System.getenv(key);
		if (environmentVariable!=null) return environmentVariable;
		String commandlineOption = System.getProperty(key);
		if (commandlineOption!=null) return commandlineOption;
		String embeddedProperty = properties.getProperty(key);
		if (embeddedProperty!=null) return embeddedProperty;
		if (required) throw new RuntimeException("Cannot find value for "+key);
		return null;
	}

}
