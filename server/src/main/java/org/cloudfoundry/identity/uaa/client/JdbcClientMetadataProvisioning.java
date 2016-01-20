package org.cloudfoundry.identity.uaa.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.Assert;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class JdbcClientMetadataProvisioning implements ClientMetadataProvisioning {

    private static final Log logger = LogFactory.getLog(JdbcClientMetadataProvisioning.class);

    private static final String CLIENT_METADATA_FIELDS = "client_id, identity_zone_id, show_on_home_page, app_launch_url, app_icon, version";
    private static final String CLIENT_METADATA_QUERY = "select " + CLIENT_METADATA_FIELDS + " from oauth_client_details where client_id=? and identity_zone_id=?";
    private static final String CLIENT_METADATAS_QUERY = "select " + CLIENT_METADATA_FIELDS + " from oauth_client_details where identity_zone_id=?";
    private static final String CLIENT_METADATA_UPDATE_FIELDS = "show_on_home_page, app_launch_url, app_icon, version";
    private static final String CLIENT_METADATA_UPDATE = "update oauth_client_details set " + CLIENT_METADATA_UPDATE_FIELDS.replace(",", "=?,") + "=?" + " where client_id=? and identity_zone_id=? and version=?";

    private JdbcTemplate template;
    private final RowMapper<ClientMetadata> mapper = new ClientMetadataRowMapper();

    JdbcClientMetadataProvisioning(JdbcTemplate template) {
        Assert.notNull(template);
        this.template = template;
    }

    public void setTemplate(JdbcTemplate template) {
        this.template = template;
    }

    @Override
    public List<ClientMetadata> retrieveAll() {
        logger.debug("Retrieving UI details for all client");
        return template.query(CLIENT_METADATAS_QUERY, mapper, IdentityZoneHolder.get().getId());
    }

    @Override
    public ClientMetadata retrieve(String clientId) {
        logger.debug("Retrieving UI details for client: " + clientId);
        return template.queryForObject(CLIENT_METADATA_QUERY, mapper, clientId, IdentityZoneHolder.get().getId());
    }

    @Override
    public ClientMetadata update(ClientMetadata resource) {
        logger.debug("Updating metadata for client: " + resource.getClientId());
        int updated = template.update(CLIENT_METADATA_UPDATE, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setBoolean(pos++, resource.isShowOnHomePage());
                URL appLaunchUrl = resource.getAppLaunchUrl();
                ps.setString(pos++, appLaunchUrl == null ? null : appLaunchUrl.toString());
                String appIcon = resource.getAppIcon();
                if (appIcon != null) {
                    byte[] decodedAppIcon = Base64.decode(appIcon.getBytes());
                    ps.setBinaryStream(pos++, new ByteArrayInputStream(decodedAppIcon), (int) decodedAppIcon.length);
                } else {
                    ps.setBinaryStream(pos++, new ByteArrayInputStream(new byte[] {}), (int) 0);
                }
                ps.setInt(pos++, resource.getVersion() + 1);
                ps.setString(pos++, resource.getClientId());
                ps.setString(pos++, IdentityZoneHolder.get().getId());
                ps.setInt(pos++, resource.getVersion());
            }
        });

        ClientMetadata resultingClientMetadata = retrieve(resource.getClientId());

        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                    "Attempt to update the UI details of client (%s) failed with incorrect version: expected=%d but found=%d",
                    resource.getClientId(),
                    resultingClientMetadata.getVersion(),
                    resource.getVersion()));
        } else if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }

        return resultingClientMetadata;
    }


    private class ClientMetadataRowMapper implements RowMapper<ClientMetadata> {

        @Override
        public ClientMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
            ClientMetadata clientMetadata = new ClientMetadata();
            int pos = 1;
            clientMetadata.setClientId(rs.getString(pos++));
            clientMetadata.setIdentityZoneId(rs.getString(pos++));
            clientMetadata.setShowOnHomePage(rs.getBoolean(pos++));
            try {
                clientMetadata.setAppLaunchUrl(new URL(rs.getString(pos++)));
            } catch (MalformedURLException mue) {
                // it is safe to ignore this as client_metadata rows are always created from a ClientMetadata instance whose launch url property is strongly typed to URL
            }
            byte[] iconBytes = rs.getBytes(pos++);
            if(iconBytes != null) { clientMetadata.setAppIcon(new String(Base64.encode(iconBytes))); }
            clientMetadata.setVersion(rs.getInt(pos++));
            return clientMetadata;
        }
    }
}