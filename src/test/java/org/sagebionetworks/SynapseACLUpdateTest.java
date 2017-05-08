package org.sagebionetworks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.sagebionetworks.repo.model.ACCESS_TYPE.DOWNLOAD;
import static org.sagebionetworks.repo.model.ACCESS_TYPE.READ;
import static org.sagebionetworks.repo.model.ACCESS_TYPE.UPDATE;
import static org.sagebionetworks.repo.model.AuthorizationConstants.BOOTSTRAP_PRINCIPAL.AUTHENTICATED_USERS_GROUP;
import static org.sagebionetworks.repo.model.AuthorizationConstants.BOOTSTRAP_PRINCIPAL.PUBLIC_GROUP;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.sagebionetworks.repo.model.ACCESS_TYPE;
import org.sagebionetworks.repo.model.AccessControlList;
import org.sagebionetworks.repo.model.ResourceAccess;

public class SynapseACLUpdateTest {

	private static final Long OWNER_ID = 101L;
	
	private static final Set<ACCESS_TYPE> READ_ONLY = new HashSet<ACCESS_TYPE>(Arrays.asList(READ));
	private static final Set<ACCESS_TYPE> READ_DOWNLOAD = new HashSet<ACCESS_TYPE>(Arrays.asList(READ, DOWNLOAD));

	
	private static AccessControlList newDto(String id) {
		AccessControlList result = new AccessControlList();
		result.setId(id);
		result.setResourceAccess(new HashSet<ResourceAccess>());
		return result;
	}
	
	private static AccessControlList add(AccessControlList acl, long principalId, Set<ACCESS_TYPE> permissions) {
		ResourceAccess ra = new ResourceAccess();
		ra.setPrincipalId(principalId);
		ra.setAccessType(permissions);
		acl.getResourceAccess().add(ra);
		return acl;
	}
	
	/*
	 * returns the permissions for the given principal in the given acl.  Also validates
	 * that the given principal only occurs once in the ACL.
	 */
	private static Set<ACCESS_TYPE> permissions(AccessControlList acl, long principalId) {
		Set<ACCESS_TYPE> result = null;
		for (ResourceAccess ra : acl.getResourceAccess()) {
			if (ra.getPrincipalId().equals(principalId)) {
				if (result==null) {
					result = ra.getAccessType();
				} else {
					throw new RuntimeException("acl has two entries for principal "+principalId);
				}
			}
		}
		return result;
	}
	
	@Test
	public void testMigrationListenerAddDownloadToRead() {
		long principalId = 999L;
		AccessControlList dto = add(newDto(OWNER_ID.toString()), principalId, READ_ONLY);
		
		// method under test
		boolean changed = SynapseACLUpdate.transformACL(dto);

		assertTrue(changed);	
		
		assertEquals(READ_DOWNLOAD, permissions(dto, principalId));
	}
	
	@Test
	public void testMigrationListenerPublicRead() {
		AccessControlList dto = add(newDto(OWNER_ID.toString()), PUBLIC_GROUP.getPrincipalId(), READ_ONLY);
		
		// method under test
		boolean changed = SynapseACLUpdate.transformACL(dto);
				
		// there are now two entries in the ACL.
		assertEquals(2, dto.getResourceAccess().size());
		// public still has read only
		assertEquals(READ_ONLY, permissions(dto, PUBLIC_GROUP.getPrincipalId()));
		// authenticated users has read + download
		assertEquals(READ_DOWNLOAD, permissions(dto, AUTHENTICATED_USERS_GROUP.getPrincipalId()));
	}
	
	@Test
	public void testMigrationListenerPublicReadAuthUserAlreadyInACL() {
		AccessControlList dto = add(newDto(OWNER_ID.toString()), PUBLIC_GROUP.getPrincipalId(), READ_ONLY);
		dto = add(dto, AUTHENTICATED_USERS_GROUP.getPrincipalId(), new HashSet<ACCESS_TYPE>(Arrays.asList(UPDATE)));
		
		// method under test
		boolean changed = SynapseACLUpdate.transformACL(dto);
		
		assertTrue(changed);	
		
		// there are now two entries in the ACL.
		assertEquals(2, dto.getResourceAccess().size());
		// public still has read only
		assertEquals(READ_ONLY, permissions(dto, PUBLIC_GROUP.getPrincipalId()));
		// authenticated users has read + download
		assertEquals(new HashSet<ACCESS_TYPE>(Arrays.asList(DOWNLOAD, READ, UPDATE)), 
				permissions(dto, AUTHENTICATED_USERS_GROUP.getPrincipalId()));
	}
	
	@Test
	public void testMigrationListenerRemovePublicDownload() {
		AccessControlList dto = add(newDto(OWNER_ID.toString()), PUBLIC_GROUP.getPrincipalId(), READ_DOWNLOAD);
		
		// method under test
		boolean changed = SynapseACLUpdate.transformACL(dto);
		
		assertTrue(changed);	
		
		// there are now two entries in the ACL.
		assertEquals(2, dto.getResourceAccess().size());
		// public still has read only
		assertEquals(READ_ONLY, permissions(dto, PUBLIC_GROUP.getPrincipalId()));
		// authenticated users has read + download
		assertEquals(READ_DOWNLOAD, permissions(dto, AUTHENTICATED_USERS_GROUP.getPrincipalId()));
	}
	
	@Test
	public void testMigrationListenerNoChange() {
		long principalId = 999L;
		AccessControlList dto = add(newDto(OWNER_ID.toString()), principalId, new HashSet<ACCESS_TYPE>(Arrays.asList(UPDATE)));
		
		// method under test
		boolean changed = SynapseACLUpdate.transformACL(dto);
		
		assertFalse(changed);	
	}
	


}
