/*
*  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.mitre.demo.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.ResourceManager;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ResourceManagerImpl implements ResourceManager {

    private static final Log log = LogFactory.getLog(ResourceManagerImpl.class);

    private static final MitreConnectDao oidcDao = new MitreConnectDao();

    /**
     * This Method will talk to APIResource registration end point  of  authorization server and creates a new resource
     *
     * @param api                this is a API object which contains all details about a API.
     * @param resourceAttributes this param will contains additional details if required.
     * @return true if sucessfully registered. false if there is a error while registering a new resource.
     * @throws APIManagementException
     */
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {

        String resourceRegistrationEndpoint = getKeyManagerConfig().getFirstProperty(MITREConstants
                .RESOURCE_REGISTRATION_ENDPOINT);
        HttpPost httpPost = new HttpPost(resourceRegistrationEndpoint.trim());
        HttpClient httpClient = getHttpClient();

        //Set scopes = (Set) externalResource.getResoruceAttribute(MITConstants.SCOPES);
        Set scopes = (Set) api.getScopes();
        //This map will hold all objects that need to be convert to json.
        Map<String, Object> paramMap = new HashMap<String, Object>();
        //initiate StringBuilder
        StringBuilder stringBuilder = new StringBuilder();
        //empty string will be append to make error message more readable.
        String scopesString = null;
        for (Object scope : scopes) {
            //Append error messages.
            scopesString = stringBuilder.append(((Scope) scope).getKey()).append(MITREConstants.SPACE_CHARACTER).
                    toString();
        }
        paramMap.put(MITREConstants.SCOPE, scopesString);

        String jsonStringOfScopes = JSONObject.toJSONString(paramMap);

        if (log.isDebugEnabled()) {
            log.debug("Creating new app using this json string " + jsonStringOfScopes);
        }
        BufferedReader reader;
        try {
            //set jsonString
            httpPost.setEntity(new StringEntity(jsonStringOfScopes, MITREConstants.UTF_8));
            //set content type headers.
            httpPost.setHeader(MITREConstants.CONTENT_TYPE, MITREConstants.APPLICATION_JSON_CONTENT_TYPE);
            //this variable will hold any error messages that are generated from DCR.
            String errorMessage = null;
            //execute httpPost request
            HttpResponse response = httpClient.execute(httpPost);
            //get HTTP response code
            int responseCode = response.getStatusLine().getStatusCode();
            //parsed json strings will be hold here.
            JSONObject parsedObject;
            //get entity from response body
            HttpEntity entity = response.getEntity();
            //read entity
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));
            try {
                // if responseCode 200 || 201
                if (HttpStatus.SC_CREATED == responseCode || HttpStatus.SC_OK == responseCode) {
                    //pass bufferReader object  and  retrieve  the parsedJson object from it.
                    parsedObject = getParsedObjectByReader(reader);
                    if (parsedObject != null) {

                        //save oAuth application record in client_info table.
                        oidcDao.saveNewResource(parsedObject, api.getId().toString());
                        return true;
                    } else {
                        handleException("Error while creating new resource at OIDC. Parsed json object is empty.");
                    }
                }//if HTTP response code is 400||401
                else if (HttpStatus.SC_BAD_REQUEST == responseCode || HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    //read Error response from buffer reader object and get json parsed object.
                    parsedObject = getParsedObjectByReader(reader);
                    //read json parsed object and extract error messages.
                    if (HttpStatus.SC_BAD_REQUEST == responseCode) {
                        errorMessage = getErrorResponse(parsedObject, "Bad request has been sent to OIDC While trying" +
                                " to register new resource.");
                    } else if (HttpStatus.SC_UNAUTHORIZED == responseCode) {
                        errorMessage = getErrorResponse(parsedObject, "Unauthorized access to OIDC");
                    }
                    //throw an exception with error message.
                    handleException(errorMessage);
                }//for other HTTP error codes we just pass generic message.
                else {
                    handleException("Some thing wrong here when registering new resource at OIDC. " +
                            "HTTP Error response code is " + responseCode);
                }
            } catch (ParseException e) {
                handleException("Error while parsing response json at new resource registration", e);
            } finally {
                //close buffer reader.
                if (reader != null) {
                    reader.close();
                }
            }
        } catch (UnsupportedEncodingException e) {
            handleException("Some thing wrong here when registering new resource at OIDC. Un-supported encoding issue" +
                    ". ", e);
        } catch (IOException e) {
            handleException("Error while reading response body from OIDC at new resource registration.", e);
        } finally {
            httpClient.getConnectionManager().shutdown();
        }
        return false;
    }

    /**
     * This method will be used to retrieve registered resource by given API ID.
     *
     * @param apiId APIM api id.
     * @return It will return a Map with registered resource details.
     * @throws APIManagementException
     */
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        if (apiId != null) {
            return oidcDao.getRegisteredResourceByAPIId(apiId);
        } else {
            handleException("Can not retrieve registered resource api id is empty");
        }
        return null;
    }

    /**
     * This method is responsible for update given APIResource  by its resourceId.
     *
     * @param  api this is a API object which contains all details about a API.
     * @param  resourceAttributes this param will contains additional details if required.
     * @return TRUE|FALSE. if it is successfully updated it will return TRUE or else FALSE.
     * @throws APIManagementException
     */
    public boolean updateRegisteredResource(API api , Map resourceAttributes) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Updating a new oAuthApp in OIDC server..");
        }
        String resourceId = (String)resourceAttributes.get(MITREConstants.RESOURCE_ID);
        if (resourceId == null) {
            handleException("resource update is failed because of empty resourceID.");
        }
        if (log.isDebugEnabled()) {
            log.debug("update registered resource with resource id =  " + resourceId);
        }
        //This map will hold all objects that need to be convert to json.
        Map<String, Object> paramMap = new HashMap<String, Object>();
        //client registration URL.
        Set scopes = (Set) api.getScopes();
        //initiate StringBuilder
        StringBuilder stringBuilder = new StringBuilder();
        //empty string will be append to make error message more readable.

        String scopesString = null;
        for (Object scope : scopes) {
            //Append error messages.
            scopesString = stringBuilder.append(((Scope) scope).getKey()).append(MITREConstants.SPACE_CHARACTER).
                    toString();
        }
        String clientId = (String) resourceAttributes.get(MITREConstants.CLIENT_ID);
        String registrationClientUrl = (String) resourceAttributes.get(MITREConstants.
                REGISTRATION_CLIENT_URI);
        String registrationAccessToken = (String) resourceAttributes.get(MITREConstants.
                REGISTRAION_ACCESS_TOKEN);

        paramMap.put(MITREConstants.SCOPE, scopesString);
        paramMap.put(MITREConstants.CLIENT_ID, clientId);

        String jsonString = JSONObject.toJSONString(paramMap);
        //initiate HTTP client.
        HttpClient client = getHttpClient();
        try {
            //initiate HTTP PUT as we are going to perform update task.
            HttpPut httpPut = new HttpPut(registrationClientUrl);
            httpPut.setEntity(new StringEntity(jsonString, MITREConstants.UTF_8));
            //set content type.
            httpPut.setHeader(MITREConstants.CONTENT_TYPE, MITREConstants.APPLICATION_JSON_CONTENT_TYPE);
            //set oAuth header with user access token to config URL.
            httpPut.setHeader(MITREConstants.AUTHORIZATION, MITREConstants.BEARER_SPACE + registrationAccessToken);
            HttpResponse response = client.execute(httpPut);
            //get the HTTP response code.
            int responseCode = response.getStatusLine().getStatusCode();
            if (log.isDebugEnabled()) {
                log.debug("update registered resource returned response code=  " + responseCode);
            }
            JSONObject parsedObject;
            //get response message content body from response.
            HttpEntity entity = response.getEntity();
            //This variable will be used to store error message.
            String errorMessage = null;
            //read response stream.
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), MITREConstants.UTF_8));
            try {

                if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                    //pass bufferReader object  and get read it and retrieve  the parsedJson object
                    parsedObject = getParsedObjectByReader(reader);
                    if (parsedObject != null) {
                        //update registered resource local database.
                        oidcDao.updateRegisteredResource(parsedObject);
                    } else {
                        handleException("Error while updating a resource at OIDC. Response is empty.");
                    }
                }//if HTTP response code is 400||401
                else if (HttpStatus.SC_BAD_REQUEST == responseCode || HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    //read Error response from buffer reader object and get json parsed object.
                    parsedObject = getParsedObjectByReader(reader);
                    //read json parsed object and extract error messages.
                    if (HttpStatus.SC_BAD_REQUEST == responseCode) {
                        errorMessage = getErrorResponse(parsedObject, "Bad request has been sent to OIDC while trying" +
                                " to update registered resource");
                    } else if (HttpStatus.SC_UNAUTHORIZED == responseCode) {
                        errorMessage = getErrorResponse(parsedObject, "Unauthorized access to OIDC");
                    }
                    //throw an exception with error message.
                    handleException(errorMessage);
                }//for other HTTP error codes we just pass generic message.
                else {
                    handleException("Some thing wrong here when updating resource. Error code" +
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
            handleException("Some thing wrong here when updating a resource at OIDC UnsupportedEncodingException ", e);
        } catch (IOException e) {
            handleException("Error while reading response body from OIDC ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
        return false;
    }

    /**
     * This method will accept resource id  as a parameter  and will delete the registered resource.
     *
     * @param apiId Resource id
     * @throws APIManagementException
     */
    @Override
    public void deleteRegisteredResourceByAPIId(String apiId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Creating a new oAuthApp in OIDC server..");
        }
        //retrieve oAuthApplication data by consumer key from CLIENT_INFO table.
        Map registeredResource = oidcDao.getRegisteredResourceByAPIId(apiId);
        //config URL.
        String configURL = (String) registeredResource.get(MITREConstants.REGISTRATION_CLIENT_URI);
        //config access token.
        String configURLsAccessToken = (String) registeredResource.get(MITREConstants.REGISTRAION_ACCESS_TOKEN);
        HttpClient client = getHttpClient();
        try {
            if (configURL != null) {
                HttpDelete httpDelete = new HttpDelete(configURL);
                // add request header
                httpDelete.addHeader(MITREConstants.AUTHORIZATION, MITREConstants.BEARER_SPACE + configURLsAccessToken);
                HttpResponse response = client.execute(httpDelete);
                int responseCode = response.getStatusLine().getStatusCode();
                if (log.isDebugEnabled()) {
                    log.debug("Delete registered resource with apiId :  " + apiId);
                }
                if (HttpStatus.SC_CREATED == responseCode || HttpStatus
                        .SC_OK == responseCode || HttpStatus.SC_NO_CONTENT == responseCode) {
                    oidcDao.deleteRegisteredResourceByAPIId(apiId);
                } else if (HttpStatus.SC_BAD_REQUEST == responseCode) {
                    handleException("Bad request has sent to OIDC while deleting registered resource");
                } else if (HttpStatus.SC_UNAUTHORIZED == responseCode) {
                    handleException("Unauthorized access to OIDC while deleting registered resource. Error code " +
                            responseCode);
                }
            }

        } catch (IOException e) {
            handleException("Error while deleting registered resource ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }

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
     * This method will return HttpClient object.
     *
     * @return HttpClient object.
     */
    private HttpClient getHttpClient() {
        HttpClient httpClient = new DefaultHttpClient();
        return httpClient;
    }

    /**
     * This method will take BufferReader object as a parameter and will do the jsonParse process and will return the
     * parsed Object.
     *
     * @param reader Buffer reader object of OIDC response entity.This might be either success response or error
     *               response.
     * @return parsedObject this will return json parsed reader object.
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
     * This method will get json parsed Object of error responses and will read and return exact error.
     *
     * @param parsedObject this is a object of JSONObject which has error response wrapped.
     * @return errorMessage this will return  processed error message as a string.
     */
    private String getErrorResponse(JSONObject parsedObject, String customErrorMessage) {

        //initiate two variables, these variables will be used to build proper error message.
        String errorMessageSubject = null;
        String errorMessageDescription = null;
        //Initiate complete error message string
        String errorMessage;

        //parsedObject should be a instance of java map.
        if (parsedObject != null) {
            //extract 'error' element.
            if (parsedObject.get("error") instanceof String) {
                errorMessageSubject = (String) parsedObject.get("error");
            }
            //extract 'error_description' element
            if (parsedObject.get("error_description") instanceof String) {
                errorMessageDescription = (String) parsedObject.get("error_description");
            }
            //initiate StringBuilder
            StringBuilder stringBuilder = new StringBuilder();

            //Append error messages.
            errorMessage = stringBuilder.append(customErrorMessage).append(MITREConstants.SPACE_CHARACTER).
                    append(errorMessageSubject)
                    .append(MITREConstants.SPACE_CHARACTER).append(errorMessageDescription).toString();

        } else {
            //user defined customer error
            errorMessage = customErrorMessage;
        }
        return errorMessage;
    }
    /**
     * This method will return APIManagerConfiguration instance. We can use this instance in order to talk to
     * key-manager.xml elements
     *
     * @return configuration. Instance of key manager config file.
     */
    private APIManagerConfiguration getKeyManagerConfig() throws APIManagementException {
        APIManagerConfiguration configuration = new APIManagerConfiguration();
        String filePath = CarbonUtils.getCarbonHome() + File.separator + "repository" +
                File.separator + "conf" + File.separator + "key-manager.xml";
        configuration.load(filePath);
        return configuration;
    }

}
