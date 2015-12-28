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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;

import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This DAO class will handle all the database specific functions.
 */
public class MitreConnectDao {

    private static volatile DataSource externalKeyManagerDataSource = null;
    private static final String AUTH_DATA_SOURCE_NAME = "OauthServerClientDataSource";

    //initiate ApiMgtDAO.
    private static final ApiMgtDAO apiMgtDAO = new ApiMgtDAO();
    //initiate logging.
    private static final Log log = LogFactory.getLog(MitreConnectDao.class);

    /**
     * common method to throw exceptions this will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException
     */
    private static void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * Insert new semi-manual oAuth app.
     *
     * @param oAuthApplicationInfo- This parameter object will contain necessary information,
     *                              which will be needed to create a semi-manual client
     * @throws APIManagementException
     */
    public void createMappedClient(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {


        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String sqlQuery = "INSERT INTO CLIENT_INFO( " +
                    "CLIENT_ID," +
                    "CONSUMER_KEY," +
                    "CONSUMER_SECRET," +
                    "CLIENT_NAME," +
                    "CONFIGURATION_URL," +
                    "CONFIG_ACCESS_TOKEN," +
                    "CLIENT_TYPE) " +
                    " VALUES(?,?,?,?,?,?,?) ";

            ps = connection.prepareStatement(sqlQuery);
            String guid = oAuthApplicationInfo.getClientId();
            if (guid == null) {
                guid = UUIDGenerator.generateUUID();
            }
            ps.setString(1, guid);
            ps.setString(2, oAuthApplicationInfo.getClientId());
            ps.setString(3, (String) oAuthApplicationInfo.getParameter(MITREConstants.CLIENT_SECRET));
            ps.setString(4, (String) oAuthApplicationInfo.getParameter(MITREConstants.CLIENT_NAME));

            if (oAuthApplicationInfo.getParameter(MITREConstants.REGISTRATION_CLIENT_URI) != null) {
                ps.setString(5, (String) oAuthApplicationInfo.getParameter(MITREConstants.REGISTRATION_CLIENT_URI));
            } else {
                ps.setString(5, null);
            }
            if (oAuthApplicationInfo.getParameter(MITREConstants.REGISTRAION_ACCESS_TOKEN) != null) {
                ps.setString(6, (String) oAuthApplicationInfo.getParameter(MITREConstants.REGISTRAION_ACCESS_TOKEN));
            } else {
                ps.setString(6, null);
            }

            ps.setString(7, "web");

            ps.execute();
            connection.commit();
        } catch (SQLException e) {
            handleException("SQL error on createMappedClient method", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, null);
        }
    }

    /**
     * This method will get apiID as a parameter and do query in RESOURCE_REGISTRATION table and retrieve data.
     *
     * @param apiId APIM api id.
     * @return will return a Map with registered resource details.
     */
    public Map getRegisteredResourceByAPIId(String apiId) throws APIManagementException {
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        Map<String, Object> registeredResourceMap = new HashMap<String, Object>();
        try {
            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String sqlQuery = "SELECT " +
                    " RESOURCE_ID," +
                    " SCOPES," +
                    " REGISTRATION_CLIENT_URI," +
                    " REGISTRATION_ACCESS_TOKEN," +
                    " CLIENT_ID," +
                    " CLIENT_SECRET," +
                    " API_ID " +
                    "FROM " +
                    " RESOURCE_REGISTRATION" +
                    " WHERE " +
                    " API_ID = ? ";

            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, apiId);
            rs = ps.executeQuery();

            while (rs.next()) {
                registeredResourceMap.put(MITREConstants.RESOURCE_ID, rs.getString("RESOURCE_ID"));
                registeredResourceMap.put(MITREConstants.SCOPES, rs.getString("SCOPES"));
                registeredResourceMap.put(MITREConstants.REGISTRATION_CLIENT_URI,
                        rs.getString("REGISTRATION_CLIENT_URI"));
                registeredResourceMap.put(MITREConstants.REGISTRAION_ACCESS_TOKEN,
                        rs.getString("REGISTRATION_ACCESS_TOKEN"));
                registeredResourceMap.put(MITREConstants.CLIENT_ID, rs.getString("CLIENT_ID"));
                registeredResourceMap.put(MITREConstants.CLIENT_SECRET, rs.getString("CLIENT_SECRET"));
                registeredResourceMap.put(MITREConstants.API_ID, rs.getString("API_ID"));
            }
        } catch (SQLException e) {
            handleException("SQL error on while populating data..", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, rs);
        }
        if(registeredResourceMap.get(MITREConstants.RESOURCE_ID) != null) {
            return registeredResourceMap;
        }else{
            return null;
        }


    }

    /**
     * This method will get response from resource registration as a jsonObject and will save a record in
     * RESOURCE_REGISTRATION table.
     *
     * @param responseFromResourceRegistration This is a JSON object which contain response from resource registration.
     * @param apiId                            This is APIM api id.
     * @throws APIManagementException
     */
    public void saveNewResource(JSONObject responseFromResourceRegistration,
                                String apiId) throws APIManagementException {

        if (apiId == null) {
            handleException("Can not create a new resource api id is empty");
        }
        Connection connection = null;
        PreparedStatement ps = null;

        try {

            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String sqlQuery = "INSERT INTO RESOURCE_REGISTRATION(" +
                    "RESOURCE_ID," +
                    "SCOPES," +
                    "REGISTRATION_CLIENT_URI," +
                    "REGISTRATION_ACCESS_TOKEN," +
                    "CLIENT_ID," +
                    "CLIENT_SECRET," +
                    "API_ID," +
                    "RESOURCE_CREATED_TIME," +
                    "RESOURCE_LAST_UPDATED_TIME)" +
                    " VALUES(?,?,?,?,?,?,?,now(),now()) ";

            ps = connection.prepareStatement(sqlQuery);
            String scope = (String) responseFromResourceRegistration.get(MITREConstants.SCOPE);
            String registrationClientURI = (String) responseFromResourceRegistration.get(MITREConstants.
                    REGISTRATION_CLIENT_URI);
            String registrationAccessToken = (String) responseFromResourceRegistration.get(MITREConstants.
                    REGISTRAION_ACCESS_TOKEN);
            String clientId = (String) responseFromResourceRegistration.get(MITREConstants.CLIENT_ID);
            String clientSecret = (String) responseFromResourceRegistration.get(MITREConstants.CLIENT_SECRET);
            ps.setString(1, clientId);//we use client_id as a resource id.
            ps.setString(2, scope);
            ps.setString(3, registrationClientURI);
            ps.setString(4, registrationAccessToken);
            ps.setString(5, clientId);
            ps.setString(6, clientSecret);
            ps.setString(7, apiId);
            ps.execute();
            connection.commit();

        } catch (SQLException e) {
            handleException("SQL error on while saving new resource", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, null);
        }
    }

    /**
     * This method updates local database table RESOURCE_REGISTRATION for the given resource with given data.
     *
     * @param registeredResource This parameter holds all the information that returned from APIResource registration
     *                           update end point as JSONObject.
     */
    public void updateRegisteredResource(JSONObject registeredResource) throws APIManagementException {
        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String clientSecret = (String) (registeredResource).get("client_secret");
            String clientName = (String) (registeredResource).get("client_name");
            String clientID = (String) (registeredResource).get("client_id");

            String SQL_QUERY =
                    "UPDATE " +
                            "CLIENT_INFO" +
                            " SET " +
                            "   CONSUMER_SECRET = ? " +
                            "   ,CLIENT_NAME = ? " +
                            "WHERE " +
                            "   CONSUMER_KEY = ?";
            ps = connection.prepareStatement(SQL_QUERY);
            ps.setString(1, clientSecret);
            ps.setString(2, clientName);
            ps.setString(3, clientID);
            ps.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            handleException("SQL error on while updating  data on CLIENT_INFO", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, null);
        }
    }

    /**
     * This method will create a new record at CLIENT_INFO.
     *
     * @param clientInformation- jsonParsed response from OIDC
     * @throws APIManagementException
     */
    public void createClientInformation(OAuthApplicationInfo clientInformation) throws APIManagementException {
        Connection connection = null;
        PreparedStatement ps = null;

        try {

            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String sqlQuery = "INSERT INTO CLIENT_INFO(" +
                    "CLIENT_ID," +
                    "CONSUMER_KEY," +
                    "CONSUMER_SECRET," +
                    "CONFIGURATION_URL," +
                    "CONFIG_ACCESS_TOKEN," +
                    "CLIENT_NAME," +
                    "REDIRECT_URI," +
                    "CLIENT_TYPE," +
                    "PAYLOAD) " +
                    " VALUES(?,?,?,?,?,?,?,?,?) ";

            ps = connection.prepareStatement(sqlQuery);
            String guid = clientInformation.getClientId();
            if (guid == null) {
                guid = UUIDGenerator.generateUUID();
            }
            ps.setString(1, guid);
            ps.setString(2, clientInformation.getClientId());
            ps.setString(3, (String) clientInformation.getParameter(ApplicationConstants.OAUTH_CLIENT_SECRET));
            ps.setString(4, (String) clientInformation.getParameter(
                    ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI));
            ps.setString(5, (String) clientInformation.getParameter(
                    ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN));

            ps.setString(6, (String) clientInformation.getParameter(ApplicationConstants.OAUTH_CLIENT_NAME));
            String redirectUri = null;
            List<String> redirect = null;

            if (clientInformation.getParameter(ApplicationConstants.OAUTH_REDIRECT_URIS) instanceof List) {
                redirect = (List<String>) clientInformation.getParameter(ApplicationConstants.OAUTH_REDIRECT_URIS);
            }

            if (redirect != null) {
                StringBuilder builder = new StringBuilder();
                for (String uri : redirect) {
                    builder.append(uri).append(",");
                }
                builder.deleteCharAt(builder.length() - 1);
                redirectUri = builder.toString();
            }

            ps.setString(7, redirectUri);
            ps.setString(8, "web");
            ps.setBlob(9, new ByteArrayInputStream("".getBytes("UTF-8")));

            ps.execute();
            connection.commit();
        } catch (SQLException e) {
            handleException("SQL error on createMappedClient method", e);
        } catch (UnsupportedEncodingException e) {
            handleException("Un-Supported Encoding type given to set payLoad..", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, null);
        }

    }

    /**
     * Get oAuthApplicaiton by consumer key and if a record is available,
     * set those values in to OAuthApplicationInfo object.
     *
     * @param consumerKey - consumerKey of the oAuthApplication.
     * @throws APIManagementException
     */
    public OAuthApplicationInfo retrieveOAuthApplicationData(String consumerKey)
            throws APIManagementException {
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        //initiate OAuthApplicationInfo.
        OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();
        try {
            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String sqlQuery = "SELECT CLIENT_ID" +
                    ",CONSUMER_KEY,CONSUMER_SECRET,CONFIGURATION_URL" +
                    ",CONFIG_ACCESS_TOKEN,PAYLOAD,CLIENT_NAME,REDIRECT_URI " +
                    " FROM CLIENT_INFO " +
                    " WHERE CONSUMER_KEY = ?";
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            rs = ps.executeQuery();
            while (rs.next()) {
                oAuthApplicationInfo.setClientId((rs.getString("CONSUMER_KEY")));
                oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET,
                        (rs.getString("CONSUMER_SECRET")));
                oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_REGISTRATION_CLIENT_URI,
                        (rs.getString("CONFIGURATION_URL")));
                oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_REGISTRATION_ACCESSTOKEN,
                        (rs.getString("CONFIG_ACCESS_TOKEN")));
                oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME,
                        (rs.getString("CLIENT_NAME")));
                oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_ID,
                        (rs.getString("CONSUMER_KEY")));
            }
        } catch (SQLException e) {
            handleException("SQL error on while populating data..", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, rs);
        }
        return oAuthApplicationInfo;
    }

    /**
     * This function will perform update client information
     *
     * @param jsonObject - JSONObject should pass here with client_secret,client_name,client_id
     * @throws APIManagementException
     */
    public void updateClientInformation(JSONObject jsonObject) throws APIManagementException {

        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String clientSecret = (String) (jsonObject).get("client_secret");
            String clientName = (String) (jsonObject).get("client_name");
            String clientID = (String) (jsonObject).get("client_id");

            String SQL_QUERY =
                    "UPDATE " +
                            "CLIENT_INFO" +
                            " SET " +
                            "   CONSUMER_SECRET = ? " +
                            "   ,CLIENT_NAME = ? " +
                            "WHERE " +
                            "   CONSUMER_KEY = ?";
            ps = connection.prepareStatement(SQL_QUERY);
            ps.setString(1, clientSecret);
            ps.setString(2, clientName);
            ps.setString(3, clientID);
            ps.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            handleException("SQL error on while updating  data on CLIENT_INFO", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(ps, connection, null);
        }
    }

    /**
     * This method will delete the records related to the application key mapping and application registrations.
     *
     * @param consumerKey - Consumer key of the application
     * @throws APIManagementException
     */
    public void deleteApplicationRecordsFromAM(String consumerKey) throws
            APIManagementException {

        Connection connection = null;
        PreparedStatement prepStmt = null;
        try {

            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String SQL_QUERY =
                    "DELETE FROM " +
                            "CLIENT_INFO " +
                            "WHERE " +
                            "   CONSUMER_KEY = ?";
            prepStmt = connection.prepareStatement(SQL_QUERY);
            prepStmt.setString(1, consumerKey);
            prepStmt.executeUpdate();
            connection.commit();

        } catch (SQLException e) {
            handleException("SQL error on while deleting  data from CLIENT_INFO", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, null);
        }

    }

    /**
     * This method will delete registered resource from RESOURCE_REGISTRATION table by given api id.
     *
     * @param APIId This is API ID.
     * @throws APIManagementException
     */
    public void deleteRegisteredResourceByAPIId(String APIId) throws APIManagementException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        try {

            connection = getExternalKeyManagerConnection();
            connection.setAutoCommit(false);
            String SQL_QUERY =
                    "DELETE FROM " +
                            "RESOURCE_REGISTRATION " +
                            "WHERE " +
                            "   API_ID = ?";
            prepStmt = connection.prepareStatement(SQL_QUERY);
            prepStmt.setString(1, APIId);
            prepStmt.executeUpdate();
            connection.commit();

        } catch (SQLException e) {
            handleException("SQL error on while deleting  data from RESOURCE_REGISTRATION", e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, null);
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
     * This method will create a database connection to the external key manager implementation database.In
     * api-manager.xml we have a config element named OauthServerClientDataSource. so in there we can set our
     * data source name. Afterwards we can put database configuration details on master-datasource.xml.
     * @return This will return Third party key manager implementation database connection.
     * @throws SQLException
     * @throws APIManagementException
     */
    public static Connection getExternalKeyManagerConnection() throws SQLException, APIManagementException {

        synchronized (APIMgtDBUtil.class) {
            APIManagerConfiguration config = ServiceReferenceHolder.getInstance().
                    getAPIManagerConfigurationService().getAPIManagerConfiguration();
            String oAuthDataSourceName = config.getFirstProperty(AUTH_DATA_SOURCE_NAME);

            if (oAuthDataSourceName != null) {
                try {
                    Context ctx = new InitialContext();
                    externalKeyManagerDataSource = (DataSource) ctx.lookup(oAuthDataSourceName);
                } catch (NamingException e) {
                    throw new APIManagementException("Error while looking up the data " +
                            "source: " + oAuthDataSourceName);
                }
            }
        }
        if (externalKeyManagerDataSource != null) {
            return externalKeyManagerDataSource.getConnection();
        } else {
            throw new SQLException("OIDC Data source is not configured properly.");
        }

    }

}
