package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class InvitationsEndpoint {

    // retrieve request
    // process request
    // return the tuple

    @RequestMapping(value = "/invite_users", method = POST, consumes = "text/plain")
    public ResponseEntity<Map<String, Object>> inviteUsers(
            @RequestParam(required = true, value = "client_id") String clientId,
            @RequestBody List<String> emails) {



        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("users", emails);
        return new ResponseEntity<>(responseBody, HttpStatus.CREATED);
    }
}
