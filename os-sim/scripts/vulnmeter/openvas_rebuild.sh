#!/bin/bash

#Checking the script is not executing
IS_RUNNING=$(ps -ef | grep "openvas_rebuild.sh" | grep -v grep | grep -v sudo | wc -l)
if [[ $IS_RUNNING -gt 2 ]]
then
    echo "openvas_rebuild.sh script already executing"
else
    /etc/init.d/openvas-manager stop

    /etc/init.d/openvas-scanner start
    i=0
    MAX_RETRIES=10

    OPENVASSD_RUNNING=`ps -Af | grep "openvassd: [Ww]aiting for incoming connections" | grep -v grep | wc -l`

    while [ $OPENVASSD_RUNNING -eq 0 ] && [ $i -lt $MAX_RETRIES ]
    do

      OPENVASSD_RUNNING=`ps -Af | grep "openvassd: [Ww]aiting for incoming connections" | grep -v grep | wc -l`
      i=$[$i+1]
      echo "Waiting 30 seconds to openvas-scanner...";
      sleep 30

    done

    /etc/init.d/openvas-manager start

    openvasmd --rebuild
fi
