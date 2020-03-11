# Spring Security LTI 1.3 Implementation

[![Build Status](https://travis-ci.com/oxctl/spring-security-lti13.svg?branch=master)](https://travis-ci.com/oxctl/spring-security-lti13)

This library adds support to Spring Security to allow LTI 1.3 launches to authenticate a user. This is still a work in progress and will be changing substantially in the near future.

## Spring Security OAuth2

This library uses [Spring Security](https://spring.io/projects/spring-security) and it's OAuth code as it's basis.

### Releasing

This project is deployed to the central repository, once ready to release you can have the release plugin tag everything:

    mvn -Prelease release:clean release:prepare
    
then if that completes successfully a release bundle can be pushed to the staging area of the Sonatype OSS repository with:

    mvn -Prelease release:perform
    
We don't automatically close the staged artifacts so after checking that the files are ok you can login to the [repository](https://oss.sonatype.org/) and release it.

