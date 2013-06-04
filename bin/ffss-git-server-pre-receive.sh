#!/bin/bash
#
# This is a git pre-receive script.
# This script should be placed in your git repositorys hook dir, like:
# /path/to/your/git/repositories/<ffss>.git/hooks/pre-receive
#
# Change the configuration to fit your needs:
# What mongodb table to insert rules to:
MONGODBTBL="ffss_rules"

while read oldrev newrev refname; do
  # Only run script for master branch
  if [[ $refname = "refs/heads/master" ]] ; then
    echo "Preparing to run tests for $newrev ... "
    TMPRDIR=$(mktemp -d)
    git archive $newrev | tar -x -C $TMPRDIR

    echo "Running tests for $newrev ... "

    cd $TMPRDIR
    /usr/local/bin/ffss-git-server-pre-commit.pl --dbname $MONGODBTBL
    rc=$?

    rm -rf $TEMPRDIR

    if [[ $rc != 0 ]] ; then
      echo "Tests failed on rev $newrev - push deniend!"
      exit $rc # Exit with non-zero if we fail!
    fi
  fi
done

# Exit with zero if all is OK
exit 0
