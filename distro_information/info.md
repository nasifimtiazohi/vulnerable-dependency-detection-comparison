mvn openmrs-sdk:setup -DserverId=distro-2-10-0 -Ddistro=referenceapplication:2.10.0 -DdbUri=jdbc:mysql://localhost:3306/distro-2-10-0 -DdbUser=root -DdbPassword=Root123 -DjavaHome="C:\Program Files\Java\jdk1.8.0_172"
this command sets up sdk distro for reference application 2.10.0.
On my mac, "mvn openmrs-sdk:setup -DserverId=test -Ddistro=referenceapplication:2.10.0 -DdbUri=jdbc:mysql://localhost:8083/test -DdbUser=root"
In my mac, to use, mysql 5.6, I use a docker container [make sure that's up].
Also, to enable java8, in my mac, on terminal just type alias command java8.


Then I have watched all projects through code. where I have also cloned it. So the next time I do openmrs-sdk:run, it builds the local projects.
Problem here:
1. make sure bower is installed globally with 'npm install -g bower'
2. legacu UI api module is giving issue with mycella license header format. Got rid of by commenting out the goal portion in legacyui pom file.
 <!-- <executions>
						<execution>
							<id>format-license-header</id>
							<phase>process-sources</phase>
							<goals>
								<goal>format</goal>
							</goals>
						</execution>
					</executions> -->

[INFO] Configured Artifact: org.openmrs.module:serialization.xstream-omod:0.2.14:jar
[INFO] ------------------------------------------------------------------------
[INFO] BUILD FAILURE
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  06:32 min
[INFO] Finished at: 2020-09-08T22:16:23-04:00
[INFO] ------------------------------------------------------------------------
[ERROR] Failed to execute goal org.openmrs.maven.plugins:openmrs-sdk-maven-plugin:3.13.6:run (default-cli) on project standalone-pom: Unable to execute mojo: Unable to find artifact. Failure to find org.openmrs.module:serialization.xstream-omod:jar:0.2.14 in http://mavenrepo.openmrs.org/nexus/content/repositories/public was cached in the local repository, resolution will not be reattempted until the update interval of openmrs-repo has elapsed or updates are forced
[ERROR] 
[ERROR] Try downloading the file manually from the project website.
[ERROR] 
[ERROR] Then, install it using the command: 
[ERROR]     mvn install:install-file -DgroupId=org.openmrs.module -DartifactId=serialization.xstream-omod -Dversion=0.2.14 -Dpackaging=jar -Dfile=/path/to/file
[ERROR] 
[ERROR] Alternatively, if you host your own repository you can deploy the file there: 
[ERROR]     mvn deploy:deploy-file -DgroupId=org.openmrs.module -DartifactId=serialization.xstream-omod -Dversion=0.2.14 -Dpackaging=jar -Dfile=/path/to/file -Durl=[url] -DrepositoryId=[id]
[ERROR] 
[ERROR] 
[ERROR]   org.openmrs.module:serialization.xstream-omod:jar:0.2.14
[ERROR] 
[ERROR] from the specified remote repositories:
[ERROR]   openmrs-repo (http://mavenrepo.openmrs.org/nexus/content/repositories/public, releases=true, snapshots=true),
[ERROR]   openmrs-repo-thirdparty (http://mavenrepo.openmrs.org/nexus/content/repositories/thirdparty, releases=true, snapshots=true),
[ERROR]   openmrs-bintray-repo (https://dl.bintray.com/openmrs/maven/, releases=true, snapshots=true),
[ERROR]   central (https://repo.maven.apache.org/maven2, releases=true, snapshots=false)
[ERROR] -> [Help 1]
[ERROR] 
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR] 
[ERROR] For more information about the errors and possible solutions, please read the following articles:
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/

4. MVN watchlist does not contain owa modules.