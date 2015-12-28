/*
 *
 *   Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package org.mitre.demo.client;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.keymgt.AbstractKeyManager;
import org.wso2.carbon.apimgt.keymgt.handlers.ResourceConstants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class consumes open APIs provided by MITRE Connect Id and implements methods for registering retrieving
 * clients. This is the main connection point that connects with APIManager.
 */
public class MitreConnectClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(MitreConnectClient.class);

    private static final MitreConnectDao mitreDao = new MitreConnectDao();

    private KeyManagerConfiguration configuration;


    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        if (keyManagerConfiguration != null) {
            this.configuration = keyManagerConfiguration;
        }
        else
        {
            APIManagerConfiguration config = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().getAPIManagerConfiguration();

            if (this.configuration == null)
                synchronized (this) {
                    this.configuration = new KeyManagerConfiguration();
                    this.configuration.setManualModeSupported(true);
                    this.configuration.setResourceRegistrationEnabled(true);
                    this.configuration.setTokenValidityConfigurable(true);
                    this.configuration.addParameter("ServerURL", config.getFirstProperty("APIKeyValidator.ServerURL"));

                    this.configuration.addParameter("Username", config.getFirstProperty("APIKeyValidator.Username"));
                    this.configuration.addParameter("Password", config.getFirstProperty("APIKeyValidator.Password"));

                    this.configuration.addParameter("RevokeURL", config.getFirstProperty("APIKeyValidator.RevokeAPIURL"));

                    String revokeUrl = config.getFirstProperty("APIKeyValidator.RevokeAPIURL");

                    String tokenUrl = revokeUrl != null ? revokeUrl.replace("revoke", "token") : null;
                    this.configuration.addParameter("TokenURL", tokenUrl);
                }
        }
    }


    /**
     * When creating an OAuthClient for the first time, this method will be executed. Within this method,
     * dynamic client registration endpoint of MITREConnect will be called.
     *
     * @param oauthAppRequest this object holds all required parameters for an OAuthClient.
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        //initiate oAuthApplicationInfo object.
        OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();
        if (log.isDebugEnabled()) {
            log.debug("Creating a new OAuth Client in MITRE Connect");
        }

        String dcrEndpoint = configuration.getParameter(MITREConstants
                                                                .DCR_ENDPOINT);

        log.debug("DCR URL is " + dcrEndpoint.trim());

        //initiate HttpPost object.
        HttpPost httpPost = new HttpPost(dcrEndpoint.trim());
        //initiate HttpClient object.
        HttpClient httpClient = getHttpClient();


        BufferedReader reader;
        try {
            //create a JSON Payload out of the properties in OAuth application.
            String jsonPayload = getJsonPayloadFromOauthApp(oAuthApplicationInfo);

            log.debug("Creating new app using payload " + jsonPayload);

            httpPost.setEntity(new StringEntity(jsonPayload, MITREConstants.UTF_8));
            httpPost.setHeader(HTTPConstants.HEADER_CONTENT_TYPE, HTTPConstants.MEDIA_TYPE_APPLICATION_JSON);

            String errorMessage = null;
            HttpResponse response = httpClient.execute(httpPost);
            int responseCode = response.getStatusLine().getStatusCode();

            JSONObject parsedObject;
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(),StandardCharsets.UTF_8));
            try {
                // Considered successful if responseCode is either 200 or 201.
                if (HttpStatus.SC_CREATED == responseCode || HttpStatus.SC_OK == responseCode) {
                    parsedObject = getParsedObjectByReader(reader);
                    if (parsedObject != null) {
                        oAuthApplicationInfo = createOAuthAppfromResponse(parsedObject);

                        // After creating the client, an access token is returned with the response,
                        // which is to be used in the subsequent calls. This access token is saved in a table.
                        mitreDao.createClientInformation(oAuthApplicationInfo);

                        return oAuthApplicationInfo;
                    } else {
                        handleException("ParseObject is empty. Can not return details of OAuth Client.");
                    }
                }
                else if (HttpStatus.SC_BAD_REQUEST == responseCode || HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    parsedObject = getParsedObjectByReader(reader);
                    if (HttpStatus.SC_BAD_REQUEST == responseCode) {
                        errorMessage = getErrorResponse(parsedObject, "MITRE Connect Received a bad request");
                    } else if (HttpStatus.SC_UNAUTHORIZED == responseCode) {
                        errorMessage = getErrorResponse(parsedObject, "Unauthorized access to MITRE Connect");
                    }
                    handleException(errorMessage);
                }//for other HTTP error codes we just pass a generic message.
                else {
                    handleException("Something went wrong while creating new client at MITRE Connect. " +
                            "HTTP Error response code is " + responseCode);
                }
            } catch (ParseException e) {
                handleException("Error while parsing response", e);
            } finally {
                if (reader != null) {
                    reader.close();
                }
            }
        } catch (UnsupportedEncodingException e) {
            handleException("Un-supported encoding issue. ", e);
        } catch (IOException e) {
            handleException("Error while reading response body from MITRE Connect ", e);
        } finally {
            httpClient.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * This method will perform update an existin OAuth Client.
     *
     * @param oauthAppRequest Captures changed details.
     * @return The response from updated OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

        log.debug("Updating an OAuthApp in MITRE Connect...");

        OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();
        String consumerKey = oAuthApplicationInfo.getClientId();
        OAuthApplicationInfo oAuthApplicationInfoFromDB = mitreDao.retrieveOAuthApplicationData(consumerKey);

        // Client registration URL and Access token are created per client. So they are to be retrieved from the DB.
        String configURL = (String) oAuthApplicationInfoFromDB.getParameter(
                ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI);
        String configURLsAccessToken = (String) oAuthApplicationInfoFromDB.getParameter(
                ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN);

        HttpClient client = getHttpClient();
        try {
            String jsonPayload = getJsonPayloadFromOauthApp(oAuthApplicationInfo);

            log.debug("updateApplication method jsonPayload:  " + jsonPayload);
            HttpPut httpPut = new HttpPut(configURL);
            httpPut.setEntity(new StringEntity(jsonPayload, "UTF8"));
            httpPut.setHeader(HTTPConstants.HEADER_CONTENT_TYPE, HTTPConstants.MEDIA_TYPE_APPLICATION_JSON);
            httpPut.setHeader(HTTPConstants.HEADER_AUTHORIZATION, MITREConstants.BEARER_SPACE + configURLsAccessToken);
            HttpResponse response = client.execute(httpPut);

            int responseCode = response.getStatusLine().getStatusCode();

            log.debug("updateApplication returned response code:  " + responseCode);

            JSONObject parsedObject;
            HttpEntity entity = response.getEntity();
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), StandardCharsets.UTF_8));
            try {
                // Consider successful if status code is 200 or 201
                if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                    parsedObject = getParsedObjectByReader(reader);
                    if (parsedObject != null) {
                        mitreDao.updateClientInformation(parsedObject);
                        createOAuthAppfromResponse(parsedObject);
                    } else {
                        handleException("Response is empty. Can not return OAuth Client details.");
                    }
                }
                else if (HttpStatus.SC_BAD_REQUEST == responseCode || HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    handleFailedResponse(reader, responseCode);
                }
                else {
                    handleException("Some thing wrong while creating new client at MITRE Connect. Error code" +
                            responseCode);
                }
            } catch (ParseException e) {
                handleException("Error while parsing response json", e);
            } finally {
                if (reader != null) {
                    reader.close();
                }
            }
        } catch (UnsupportedEncodingException e) {
            handleException("Some thing wrong while updating a client at MITRE Connect UnsupportedEncodingException ",
                            e);
        } catch (IOException e) {
            handleException("Error while reading response body from MITRE Connect ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * Delete OAuth Client from MITRE Connect and from intermediate tables.
     *
     * @param consumerKey consumer key of the OAUth Client.
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting OAuth Client in MITRE Connect ...");
        }

        OAuthApplicationInfo oAuthApplicationInfo = mitreDao.retrieveOAuthApplicationData(consumerKey);

        String configURL = (String) oAuthApplicationInfo.getParameter(
                ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI);
        String configURLsAccessToken = (String) oAuthApplicationInfo.getParameter(
                ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN);

        HttpClient client = getHttpClient();
        try {
            if (configURL != null) {
                HttpDelete httpDelete = new HttpDelete(configURL);

                httpDelete.addHeader(HTTPConstants.HEADER_AUTHORIZATION, MITREConstants.BEARER_SPACE + configURLsAccessToken);
                HttpResponse response = client.execute(httpDelete);
                int responseCode = response.getStatusLine().getStatusCode();

                log.debug("Delete application response code :  " + responseCode);

                if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK ||
                        responseCode == HttpStatus.SC_NO_CONTENT) {
                    mitreDao.deleteApplicationRecordsFromAM(consumerKey);
                } else if (HttpStatus.SC_BAD_REQUEST == responseCode) {
                    handleException("Bad request has been sent to MITRE Connect while trying to delete auth " +
                                    "application.");
                } else if (HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    handleException("Unauthorized access to MITRE Connect. Error code " + responseCode);
                }
            }
            else {
                mitreDao.deleteApplicationRecordsFromAM(consumerKey);
            }

        } catch (IOException e) {
            handleException("Error while reading response body from MITRE Connect ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    /**
     * This method retrieves OAuth Client details when given the consumer key.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @return a OAuthApplicationInfo this object contains the all details of an OAuth Client.
     * @throws APIManagementException
     */

    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        HttpClient client = getHttpClient();
        try {
            log.debug("Retrieving application for consumer id  :  " + consumerKey);

            OAuthApplicationInfo oAuthApplicationInfo = mitreDao.retrieveOAuthApplicationData(consumerKey);

            String configURL = (String) oAuthApplicationInfo.getParameter(
                    ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI);
            String configURLsAccessToken = (String) oAuthApplicationInfo.getParameter(
                    ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN);

            if (configURL != null) {
                HttpGet request = new HttpGet(configURL);
                request.addHeader(HTTPConstants.HEADER_AUTHORIZATION, MITREConstants.BEARER_SPACE + configURLsAccessToken);

                HttpResponse response = client.execute(request);
                int responseCode = response.getStatusLine().getStatusCode();

                log.debug("Retrieving application response code :  " + responseCode);

                JSONObject parsedObject;
                HttpEntity entity = response.getEntity();
                BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));
                try {
                    if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                        parsedObject = getParsedObjectByReader(reader);
                        return createOAuthAppfromResponse(parsedObject);
                    }
                    else if (HttpStatus.SC_BAD_REQUEST == responseCode || HttpStatus.SC_UNAUTHORIZED ==
                            responseCode) {
                        handleFailedResponse(reader, responseCode);
                    } else {
                        handleException("Some thing went wrong while creating new client at MITRE Connect. Error " +
                                        "code"
                                + responseCode);
                    }
                } catch (ParseException e) {
                    handleException("Error while parsing response json", e);
                } finally {
                    if (reader != null) {
                        reader.close();
                    }
                }
                // Start retrieving mapped clients. We just return what we have in CLIENT_INFO table.
            } else if (consumerKey != null) {
                return oAuthApplicationInfo;
            } else {
                handleException("Error while trying to retrieve application. Unknown retrieval method.");
            }
        } catch (IOException e) {
            handleException("Error while reading response body from MITRE Connect ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
        return null;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        tokenInfo.setAccessToken("dummy");
        return tokenInfo;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        String introspectionURL = config.getParameter(MITREConstants.INTROSPECTION_URL);
        //base64_encode(clientid:secret)
        String introspectionSecret = config.getParameter(MITREConstants.INTROSPECTION_SECRET);

        HttpPost post = new HttpPost(introspectionURL.trim());
        HttpClient client = new DefaultHttpClient();
        List<NameValuePair> tokParams = new ArrayList<NameValuePair>();
        tokParams.add(new BasicNameValuePair(ResourceConstants.AUTH_TOKEN_PARAM_NAME, accessToken));
        post.setHeader(HTTPConstants.HEADER_AUTHORIZATION, ResourceConstants.BASIC_TOKEN_NAME + " " +
                introspectionSecret.trim());

        try {
            post.setEntity(new UrlEncodedFormEntity(tokParams, ResourceConstants.UTF8_PARAM_NAME));

            log.debug("Sending post request to  introspect : " + "Introspect URI = " +
                        introspectionURL + ", Token: " + ResourceConstants.INTROSPECTION_TOKEN);
            HttpResponse response = client.execute(post);
            int responseCode = response.getStatusLine().getStatusCode();
            log.debug("HTTP Response code : " + responseCode);

            HttpEntity entity = response.getEntity();
            JSONObject parsedObject;

            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), MITREConstants.UTF_8));
            try {

                if (HttpStatus.SC_CREATED == responseCode || HttpStatus.SC_OK == responseCode) {
                    //pass bufferReader object  and get read it and retrieve  the parsedJson object
                    parsedObject = getParsedObjectByReader(reader);
                    if (parsedObject != null) {

                        Map valueMap = parsedObject;
                        Object value = valueMap.get(ResourceConstants.ACTIVE_PARAM_NAME);
                        Object issuedTime = System.currentTimeMillis()/1000;
                        Object expiryTime = valueMap.get(ResourceConstants.EXP_PARAM_NAME);

                        if (value != null) {
                            boolean active = Boolean.parseBoolean(value.toString());
                            log.debug("is token active ? " + active);

                            tokenInfo.setTokenValid((Boolean)valueMap.get(ResourceConstants.ACTIVE_PARAM_NAME));
                            tokenInfo.setEndUserName((String) valueMap.get("user_id"));
                            tokenInfo.setConsumerKey((String) valueMap.get(ResourceConstants.CLIENT_ID_PARAM_NAME));
                            tokenInfo.setValidityPeriod(((Long) expiryTime - (Long) issuedTime)*1000);
                            tokenInfo.setIssuedTime(System.currentTimeMillis());
                            String scopes[] = new String[]{(String) valueMap.get("scope")};
                            tokenInfo.setScope(scopes);
                        }
                    } else {
                        handleException("Error while validating access token. Response is empty.");
                    }
                }
                else if (HttpStatus.SC_BAD_REQUEST == responseCode || HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    handleFailedResponse(reader,responseCode);
                }
                else {
                    handleException("Some thing wrong here when updating resource. Error code" +
                            responseCode);
                }
            } catch (ParseException e) {
                handleException("Error while parsing response json " + e.getMessage(), e);
            } finally {
                if (reader != null) {
                    reader.close();
                }
            }
        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("Error occurred while sending request to introspect URL. " +
                    e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error occurred while reading or closing buffer reader. " + e.getMessage(), e);
        }

        return tokenInfo;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * When providing client details from the UI, this method will be called.
     *
     * @param oAuthAppRequest Client details provided through the UI will be contained in this object.
     * @return Details of the OAuth Application saved.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        String tokenScopes[] = new String[1];
        tokenScopes[0] = "default";
        oAuthApplicationInfo.addParameter("tokenScope", tokenScopes);

        log.debug("Saving client details for the OAuth Client with id  :  " +
                  oAuthApplicationInfo.getClientId());

        //Insert a record to CLIENT_INFO table.
        mitreDao.createMappedClient(oAuthApplicationInfo);
        return oAuthApplicationInfo;
    }

    @Override
    public AccessTokenRequest buildAccessTokenRequestFromJSON(String jsonInput,AccessTokenRequest tokenRequest) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
                                                                  AccessTokenRequest tokenRequest) throws APIManagementException {
        return null;
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }


    private void handleFailedResponse(BufferedReader reader, int responseCode)
            throws APIManagementException, IOException, ParseException {
        String errorMessage= "";

        //read Error response from buffer reader object and get json parsed object.
        JSONObject parsedObject = getParsedObjectByReader(reader);
        //read json parsed object and extract error messages.
        if (HttpStatus.SC_BAD_REQUEST == responseCode) {
            errorMessage = getErrorResponse(parsedObject, "Bad request has been sent to OIDC");
        } else if (HttpStatus.SC_UNAUTHORIZED == responseCode) {
            errorMessage = getErrorResponse(parsedObject, "Unauthorized access to OIDC");
        }
        //throw an exception with error message.
        handleException(errorMessage);
    }

    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     * common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException
     */
    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * This method will create OAuthApplicationInfo object from response map.
     *
     * @param responseMap OAuth application parameters will be put in this object.
     * @return {@link OAuthApplicationInfo}.
     */
    private OAuthApplicationInfo createOAuthAppfromResponse(Map responseMap) {
        OAuthApplicationInfo info = new OAuthApplicationInfo();

        Object clientId = responseMap.get(ApplicationConstants.OAUTH_CLIENT_ID);
        info.setClientId((String) clientId);

        Object clientSecret = responseMap.get(ApplicationConstants.OAUTH_CLIENT_SECRET);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET, clientSecret);

        //set client id as a parameter.
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_ID,  clientId);

        //set config URL.
        Object configUrl = responseMap.get(ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI, configUrl);

        //set config accessToken
        Object configAccessToken = responseMap.get(ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN, configAccessToken);

        //set client Name.
        Object clientName = responseMap.get(ApplicationConstants.OAUTH_CLIENT_NAME);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, clientName);

        //set redirect URL
        Object redirectURI = responseMap.get(ApplicationConstants.OAUTH_REDIRECT_URIS);
        info.addParameter(ApplicationConstants.OAUTH_REDIRECT_URIS, redirectURI);

        //set contacts.
        Object contact = responseMap.get(ApplicationConstants.OAUTH_CLIENT_CONTACTS);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_CONTACTS, contact);

        //set scopes
        Object scope = responseMap.get(ApplicationConstants.OAUTH_CLIENT_SCOPE);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_SCOPE, scope);

        //set grantTypes.
        Object grantType = responseMap.get(ApplicationConstants.OAUTH_CLIENT_GRANT);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_GRANT, grantType);

        //set responseType
        Object responseType = responseMap.get(ApplicationConstants.OAUTH_CLIENT_RESPONSETYPE);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_RESPONSETYPE, responseType);

        //set oAuthMethod
        Object authMethod = responseMap.get(ApplicationConstants.OAUTH_CLIENT_AUTHMETHOD);
        info.addParameter(ApplicationConstants.OAUTH_CLIENT_AUTHMETHOD, authMethod);

        return info;
    }

    /**
     * This method will return HttpClient object.
     *
     * @return HttpClient object.
     */
    private HttpClient getHttpClient() {
        HttpClient httpClient = new DefaultHttpClient();
        return httpClient;
    }

    /**
     * Utility method for parsing a reader and getting a {@link org.json.simple.JSONObject}
     *
     * @param reader Buffer reader object from response entity.This might be either success response or an error
     *               response.
     * @return {@link org.json.simple.JSONObject} as the parsedObject.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * Utility method for building an error message from the response. MITREConnect send the detailed error with the
     * response body when a failure has occurred.
     *
     * @param parsedObject an object of {@link org.json.simple.JSONObject} having the exact error.
     * @param customErrorMessage Part of the error message to be injected into the final error message.
     * @return Constructed error message as a String
     */
    private String getErrorResponse(JSONObject parsedObject, String customErrorMessage) {

        String errorMessageSubject = null;
        String errorMessageDescription = null;

        String errorMessage;

        if (parsedObject != null) {
            if (parsedObject.get("error") instanceof String) {
                errorMessageSubject = (String) parsedObject.get("error");
            }
            if (parsedObject.get("error_description") instanceof String) {
                errorMessageDescription = (String) parsedObject.get("error_description");
            }

            StringBuilder stringBuilder = new StringBuilder();

            errorMessage = stringBuilder.append(customErrorMessage).append(" ").
                    append(errorMessageSubject)
                    .append(" ").append(errorMessageDescription).toString();

        } else {
            //user defined customer error
            errorMessage = customErrorMessage;
        }
        return errorMessage;
    }


    /**
     * Create a JSON Payload out of the provided {@link org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo} object.
     *
     * @param oAuthApplicationInfo Details of OAuth Client.
     * @return The payload to be sent as a String.
     */
    private String getJsonPayloadFromOauthApp(OAuthApplicationInfo oAuthApplicationInfo) {

        Map<String, Object> paramMap = new HashMap<String, Object>();
        paramMap.put(ApplicationConstants.OAUTH_CLIENT_ID,
                     oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_ID));
        paramMap.put(ApplicationConstants.OAUTH_REDIRECT_URIS,
                     oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CALLBACK_URIS));
        paramMap.put(ApplicationConstants.OAUTH_CLIENT_NAME,
                     oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_NAME));
        if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_CONTACT) != null) {
            paramMap.put(ApplicationConstants.OAUTH_CLIENT_CONTACTS,
                         oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_CONTACT));
        }

        JSONArray scopes = (JSONArray) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_SCOPE);

        //initiate StringBuilder
        StringBuilder stringBuilder = new StringBuilder();
        String scopesString = null;
        if (scopes instanceof JSONArray && scopes != null) {
            for (int i = 0; i < scopes.size(); i++) {
                scopesString = stringBuilder.append(scopes.get(i)).append(MITREConstants.SPACE_CHARACTER).toString();
            }
        }

        paramMap.put(ApplicationConstants.OAUTH_CLIENT_SCOPE, scopesString);
        if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT) != null) {
            paramMap.put(ApplicationConstants.OAUTH_CLIENT_GRANT,
                         oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT));
        }

        if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_RESPONSETYPE) != null) {
            paramMap.put(ApplicationConstants.OAUTH_CLIENT_RESPONSETYPE,
                         oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_RESPONSETYPE));
        }

        if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_AUTHMETHOD) != null) {
            paramMap.put(ApplicationConstants.OAUTH_CLIENT_AUTHMETHOD,
                         oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_AUTHMETHOD));
        }

        return JSONObject.toJSONString(paramMap);
    }

}
