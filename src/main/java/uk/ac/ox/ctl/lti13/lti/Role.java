package uk.ac.ox.ctl.lti13.lti;

/**
 * @see <a href="https://www.imsglobal.org/spec/lti/v1p3/#role-vocabularies">https://www.imsglobal.org/spec/lti/v1p3/#role-vocabularies</a>
 */
public class Role {

    public static class System {

        // Core system roles
        public static final String ADMINISTRATOR = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator";
        public static final String NONE = "http://purl.imsglobal.org/vocab/lis/v2/system/person#None";

        // Non-core system roles
        public static final String ACCOUNT_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/system/person#AccountAdmin";
        public static final String CREATOR = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Creator";
        public static final String SYS_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysAdmin";
        public static final String SYS_SUPPORT = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysSupport";
        public static final String USER = "http://purl.imsglobal.org/vocab/lis/v2/system/person#User";
    }

    public static class Institution {

        // Core institution roles
        public static final String ADMINISTRATOR = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator";
        public static final String FACULTY = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Faculty";
        public static final String GUEST = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Guest";
        public static final String NONE = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#None";
        public static final String OTHER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Other";
        public static final String STAFF = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Staff";
        public static final String STUDENT = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student";

        // Non‑core institution roles
        public static final String ALUMNI = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Alumni";
        public static final String INSTRUCTOR = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor";
        public static final String LEARNER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Learner";
        public static final String MEMBER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Member";
        public static final String MENTOR = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Mentor";
        public static final String OBSERVER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Observer";
        public static final String PROSPECTIVE_STUDENT = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#ProspectiveStudent";
    }

    public static class Context {

        // Core context roles
        public static final String ADMINISTRATOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator";
        public static final String CONTENT_DEVELOPER = "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper";
        public static final String INSTRUCTOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor";
        public static final String LEARNER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
        public static final String MENTOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor";

        // Non‑core context roles
        public static final String MANAGER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Manager";
        public static final String MEMBER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Member";
        public static final String OFFICER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Officer";
    }
}
