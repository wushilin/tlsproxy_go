#!/bin/sh

VERSION=`cat VERSION`
ARTIFACT=`cat ARTIFACT`
rm -rf build
mkdir -p build

for GOOS in darwin freebsd linux windows
do
        for GOARCH in amd64 arm64 arm
        do
                echo "Building $GOOS/$GOARCH"
                env GOOS=$GOOS GOARCH=$GOARCH go build -o build/$ARTIFACT-$GOOS-$GOARCH-$VERSION .
                tar -C ./build -zcvf build/$ARTIFACT-$GOOS-$GOARCH-$VERSION.tar.gz $ARTIFACT-$GOOS-$GOARCH-$VERSION
        done
done
