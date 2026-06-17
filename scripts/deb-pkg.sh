#! /bin/bash
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd $SCRIPT_DIR/../ubuntu-deb 
echo $(pwd)
echo ${SCRIPT_DIR}
\cp $SCRIPT_DIR/../bin/httptrace-linux-amd64 ./sources/httptrace
fakeroot dpkg-buildpackage -us -uc -b -d
rm -f $SCRIPT_DIR/../power-httptrace_1.0.0-2_amd64.changes
rm -f $SCRIPT_DIR/../power-httptrace_1.0.0-2_amd64.buildinfo