#!bin/bash

export JAVA_HOME=$(readlink -f /usr/bin/java | sed "s:/bin/java::")
/signer-service/bin/signer-service