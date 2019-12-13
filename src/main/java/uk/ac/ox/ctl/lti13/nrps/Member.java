package uk.ac.ox.ctl.lti13.nrps;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Member {

    private String status;
    private String name;
    // URL of Avatar
    private String picture;
    @JsonProperty("given_name")
    private String givenName;
    @JsonProperty("family_name")
    private String familyName;
    private String email;
    @JsonProperty("lis_person_sourcedid")
    private String lisPersonSourcedid;
    @JsonProperty("user_id")
    private String userId;
    private List<String> roles;

    private List<Message> message;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLisPersonSourcedid() {
        return lisPersonSourcedid;
    }

    public void setLisPersonSourcedid(String lisPersonSourcedid) {
        this.lisPersonSourcedid = lisPersonSourcedid;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public List<Message> getMessage() {
        return message;
    }

    public void setMessage(List<Message> message) {
        this.message = message;
    }
}
