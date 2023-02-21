From tomcat:8.0.51-jre8-alpine
RUN rm -rf /usr/local/tomcat/webapps/*
ARG CACHEBUST=1
RUN echo "$PWD"
CMD pwd
RUN echo 'we are running some # of cool things'
COPY ./target/demos-0.1-SNAPSHOT.war /usr/local/tomcat/webapps/ROOT.war
CMD ["catalina.sh","run"]
