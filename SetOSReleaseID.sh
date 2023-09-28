#!/bin/bash

if [ $UID -ne 0 ]; then
    echo "elevated priviledges are required to run this script. exiting..."
    exit
fi

OS_RELEASE_STRING="$(grep -Pe '^ID=[a-z]+$' /etc/os-release)"

## sets how bash recognizes word 
## boundaries, default is whitespace
IFS="="

if [ ! -z "$OS_RELEASE_STRING" ]; then
    echo "grepped os-release string: $OS_RELEASE_STRING..."

    ## ARR specifies the words separates by IFS
    ## are assigned to the indices of an array
    read -a OS_RELEASE_ARR <<< "$OS_RELEASE_STRING"

    if [ "${#OS_RELEASE_ARR[@]}" -gt 1 ]; then
        OS_RELEASE_ID="${OS_RELEASE_ARR[1]}"
        echo "ACTUAL OS RELEASE ID: $OS_RELEASE_ID"
    fi
else
    echo "failed to parse your os-release file. exiting..."
    exit
fi

IFS=" "