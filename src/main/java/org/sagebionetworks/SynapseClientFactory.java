package org.sagebionetworks;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpStatus;
import org.sagebionetworks.client.SynapseClient;
import org.sagebionetworks.client.SynapseClientImpl;
import org.sagebionetworks.client.SynapseProfileProxy;


public class SynapseClientFactory {

	private static final List<Integer> NO_RETRY_STATUSES = Arrays.asList(
			HttpStatus.SC_ACCEPTED, // SynapseResultNotReadyException
			HttpStatus.SC_NOT_FOUND, // SynapseNotFoundException
			HttpStatus.SC_BAD_REQUEST, // SynapseBadRequestException
			HttpStatus.SC_PRECONDITION_FAILED, // SynapseConflictingUpdateException
			HttpStatus.SC_GONE, // SynapseDeprecatedServiceException
			HttpStatus.SC_FORBIDDEN, // SynapseForbiddenException, SynapseTermsOfUseException
			HttpStatus.SC_UNAUTHORIZED, // SynapseUnauthorizedException
			HttpStatus.SC_CONFLICT // 409
		);
		
	private static SynapseClient createSynapseClientIntern(boolean staging) {
		SynapseClientImpl scIntern = new SynapseClientImpl();
		if (staging) {
			scIntern.setAuthEndpoint("https://repo-staging.prod.sagebase.org/auth/v1");
			scIntern.setRepositoryEndpoint("https://repo-staging.prod.sagebase.org/repo/v1");
			scIntern.setFileEndpoint("https://repo-prod.staging.sagebase.org/file/v1");
		} else {
			scIntern.setAuthEndpoint("https://repo-prod.prod.sagebase.org/auth/v1");
			scIntern.setRepositoryEndpoint("https://repo-prod.prod.sagebase.org/repo/v1");
			scIntern.setFileEndpoint("https://repo-prod.prod.sagebase.org/file/v1");
		}

		return SynapseProfileProxy.createProfileProxy(scIntern);
	}

	public static SynapseClient createSynapseClient(boolean staging) {
		final SynapseClient synapseClientIntern = createSynapseClientIntern(staging);
		
		final ExponentialBackoffRunner exponentialBackoffRunner = new ExponentialBackoffRunner(
				NO_RETRY_STATUSES, ExponentialBackoffRunner.DEFAULT_NUM_RETRY_ATTEMPTS);

		InvocationHandler handler = new InvocationHandler() {
			public Object invoke(final Object proxy, final Method method, final Object[] args)
					throws Throwable {
				return exponentialBackoffRunner.execute(new Executable<Object>() {
					public Object execute() throws Throwable {
						try {
							return method.invoke(synapseClientIntern, args);
						} catch (IllegalAccessException  e) {
							throw new RuntimeException(e);
						} catch (InvocationTargetException e) {
							if (e.getCause()==null) throw e; else throw e.getCause();
						}
					}
				});
			}
		};
			
		return (SynapseClient) Proxy.newProxyInstance(SynapseClient.class.getClassLoader(),
				new Class[] { SynapseClient.class },
				handler);
	}

}
