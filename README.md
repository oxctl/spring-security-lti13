# Spring Security LTI 1.3 Implementation

[![Build and publish](https://github.com/oxctl/spring-security-lti13/actions/workflows/push.yml/badge.svg)](https://github.com/oxctl/spring-security-lti13/actions/workflows/push.yml)

This library adds support to Spring Security to allow LTI 1.3 launches to authenticate a user. This is still a work in progress and will be changing substantially in the near future.

## Spring Security OAuth2

This library uses [Spring Security](https://spring.io/projects/spring-security) and it's OAuth code as its basis.

## Using

This [library](https://search.maven.org/artifact/uk.ac.ox.ctl/spring-security-lti13) is released to maven central and can be added to your maven project with the following project coordinates:

```xml
    <dependency>
        <groupId>uk.ac.ox.ctl</groupId>
        <artifactId>spring-security-lti13</artifactId>
        <version>0.3.2</version>
    </dependency>
```

There is a [demo project](https://github.com/oxctl/spring-security-lti13-demo) built using this library that may be helpful in getting started with the project.

### Development Builds

If you want to use the latest (unstable) unreleased version of the library in your project builds are published to GitHub packages. To use this version in your project you need to add the GitHub packages repository to your `pom.xml`:

```xml
    <repositories>
        <repository>
            <id>oxctl/spring-security-lti13</id>
            <url>https://maven.pkg.github.com/oxctl/spring-security-lti13</url>
            <snapshots>
                <enabled>true</enabled>
            </snapshots>
            <releases>
                <enabled>false</enabled>
            </releases>
        </repository>
    </repositories>
```

then add the `SNAPSHOT` version of the library to your `pom.xml`:

```xml
    <dependency>
        <groupId>uk.ac.ox.ctl</groupId>
        <artifactId>spring-security-lti13</artifactId>
        <version>0.2.1-SNAPSHOT</version>
    </dependency>
```

However, this should just be for testing until a new version is released to Maven Central.

### Releasing

The project is deployed to the central repository, once ready to release use the release plugin to tag everything:

```bash
    mvn -Prelease,sonatype release:clean release:prepare
```

then if that completes successfully a release bundle can be pushed to the staging area of the Sonatype OSS repository with:

```bash
    mvn -Prelease,sonatype release:perform
```
    
We don't automatically close the staged artifacts so after checking that the files are ok you should login to the [repository](https://oss.sonatype.org/) and release it. The version in the README.md should also be updated so that people using the project get the latest version and the demo project should be updated to use the latest version.

## References

 - Learning Tools Interoperability Core Specification - https://www.imsglobal.org/spec/lti/v1p3
 - 1 EdTech Security Framework - https://www.imsglobal.org/spec/lti/v1p3
 - OpenID Connect Core - https://openid.net/specs/openid-connect-core-1_0.html
