#!/bin/bash

if [ "$#" -ne 1 ] || [ "$1" != "course-marker" ]; then
	echo "ERROR: expected one argument: course-marker"
	exit 1
fi

printf '%s\n' "course-marker" > "$HOME/csce765-agentsec/hw1/markers/marker.txt"
