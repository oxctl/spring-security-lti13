package uk.ac.ox.ctl.lti13.nrps;

import java.util.List;

/**
 * A Response back from the Names and Roles Provisioning Service.
 * I couldn't find a formal definition of this and it looks like there isn't one so it's modeled on examples from Canvas.
 *
 * @see <a href="https://www.imsglobal.org/spec/lti-nrps/v2p0#sharing-of-personal-data">https://www.imsglobal.org/spec/lti-nrps/v2p0#sharing-of-personal-data</a>
 */
public class NRPSResponse {

    private String id;
    private Context context;
    private List<Member> members;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public List<Member> getMembers() {
        return members;
    }

    public void setMembers(List<Member> members) {
        this.members = members;
    }
}
