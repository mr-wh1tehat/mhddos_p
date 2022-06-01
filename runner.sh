#!/bin/bash

BRANCH="main"
PID=""

RED="\033[1;31m"
GREEN="\033[1;32m"
RESET="\033[0m"

PYTHON=$1
SCRIPT_ARGS="${@:2}"

trap 'shutdown' SIGINT SIGQUIT SIGTERM ERR

function shutdown() {
    stop_script
    exit
}

function stop_script() {
  if [ -n "$PID" ];
  then
    kill -INT $PID
    wait $PID
    PID=""
  fi
}

function update_script() {
    git reset -q --hard
    git checkout -q $BRANCH
    git pull -q
    $PYTHON -m pip install -q -r requirements.txt
}

while true
do

  git fetch -q origin $BRANCH

  if [ -n "$(git diff --name-only origin/$BRANCH)" ]
  then
    echo -e "\n${GREEN}[$(date +"%d-%m-%Y %T")] - New version available, updating the script!${RESET}\n"
    stop_script
    update_script
    exec ./runner.sh $PYTHON $SCRIPT_ARGS
  fi

  while [ -z "$PID" ]
  do
    $PYTHON runner.py $SCRIPT_ARGS & PID=$!
    sleep 1
    if ! kill -0 $PID
    then
      PID=""
      echo -e "\n${RED}Error starting - retry in 30 seconds! Ctrl+C to exit${RESET}\n"
      sleep 30
    fi
  done

  sleep 666

done
