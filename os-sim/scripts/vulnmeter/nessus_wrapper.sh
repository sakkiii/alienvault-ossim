#!/bin/bash
#
# Copyright (c) 2017 by T-Systems Austria GesmbH - Daniel Kissler
# cyber-defense-services@t-systems.at
#
# Transforms a Nessus v6 .csv report to a .nbe file to import them to AlienVault.
#
# v1.0 - initial release
#

if [ $# == 1 ]
  then
    tail -n+2 $1 |sed ':a;N;$!ba;s/\n/\\n/g;s/\r/\n/g'| sed 's/^[^"]*"//g;s/"$//g' | gawk -F '","' '{print "results|" $5 "|" $5 "|" $7 "/" $6 "|" $1 "|Security Note|Synopsis :\\n\\n" $9 " \\n\\nDescription :\\n\\n" $10 " \\n\\nSolution :\\n\\n" $11 " \\n\\nRisk Factor :\\n\\n" $4 " / CVSS Base Score: " $3 " \\n\\nPlugin output :\\n\\n" $13 " \\n\\nCVE:" $2 "\\n"}' > $1.nbe
    echo "File $1.nbe created"
  else
    echo "Illegal number of parameters"
fi
