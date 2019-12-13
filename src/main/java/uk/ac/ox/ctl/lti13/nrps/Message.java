package uk.ac.ox.ctl.lti13.nrps;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.ac.ox.ctl.lti13.lti.Claims;

import java.util.Map;

/**
 * This is the additional message that comes back you pass through a resource link ID.
 */
public class Message {

    private String locale;

    @JsonProperty(Claims.CUSTOM)
    private Map<String, String> custom;

    @JsonProperty(Claims.MESSAGE_TYPE)
    private String messageType;

    @JsonProperty("https://www.instructure.com/canvas_user_id")
    private Integer canvasUserId;

    @JsonProperty("https://www.instructure.com/canvas_user_login_id")
    private String canvasLoginId;

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public Map<String, String> getCustom() {
        return custom;
    }

    public void setCustom(Map<String, String> custom) {
        this.custom = custom;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public Integer getCanvasUserId() {
        return canvasUserId;
    }

    public void setCanvasUserId(Integer canvasUserId) {
        this.canvasUserId = canvasUserId;
    }

    public String getCanvasLoginId() {
        return canvasLoginId;
    }

    public void setCanvasLoginId(String canvasLoginId) {
        this.canvasLoginId = canvasLoginId;
    }
}
