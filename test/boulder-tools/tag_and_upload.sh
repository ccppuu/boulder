#!/bin/bash -e

cd $(dirname $0)

DATESTAMP=$(date +%Y-%m-%d)
BASE_TAG_NAME="letsencrypt/boulder-tools"
GO_VERSIONS=( "1.10" "1.10.1" )

# Build a tagged image for each GO_VERSION
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="$BASE_TAG_NAME-go$GO_VERSION:$DATESTAMP"
  echo "Building boulder-tools image $TAG_NAME"

  # TODO(@cpu): proper tempfile?
  DOCKERFILE="golang.$GO_VERSION.Dockerfile"

  # TODO(@cpu): Comment the unfortunate WHY of this
  sed -r \
    -e 's!%%GO_VERSION%%!'"$GO_VERSION"'!g' \
    "Dockerfile.tmpl" > "$DOCKERFILE"

  docker build . \
    -t $TAG_NAME \
    --no-cache \
    -f "$DOCKERFILE"

  # TODO(@cpu): Move this to an at-exit handler
  rm "$DOCKERFILE"
done

# Log in once now that images are ready to upload
echo "Images ready, please login to allow Dockerhub push"
docker login

# Upload a tagged image for each GO_VERSION
for GO_VERSION in "${GO_VERSIONS[@]}"
do
  TAG_NAME="$BASE_TAG_NAME-go$GO_VERSION:$DATESTAMP"
  echo "Pushing $TAG_NAME to Dockerhub"
  docker push $TAG_NAME
done
