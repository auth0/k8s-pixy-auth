#!/bin/bash
set -e

# package pulls the build binary for the platform ($1). If you pass in a file 
# extension ($2) it will be used on the binaries
function package {
    local PLATFORM=$1
    local FILE_EXTENSION=$2

    local ARCHIVE_NAME="k8s-pixy-auth-$VERSION-$PLATFORM-amd64.tar.gz"
    echo "Packaging into $ARCHIVE_NAME:"
    tar -czvf ./deploy/$ARCHIVE_NAME ./binaries/$PLATFORM/k8s-pixy-auth$FILE_EXTENSION
}

DEPLOY_STAGING_DIR=./deploy-staging
ECHO_VERSION=$(make echo-version)
VERSION="$(echo $ECHO_VERSION | awk 'match($0, /([0-9]*\.[0-9]*\.[0-9]*)$/) { print substr($0, RSTART, RLENGTH) }')"
echo "Working on version: $VERSION"

# make needed directories
rm -rf deploy
mkdir deploy

package linux
package darwin
package windows .exe