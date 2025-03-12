#!/bin/bash
set -e

# Check if required arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <container_name> <new_image>"
    echo "Example: $0 my-container nginx:latest"
    exit 1
fi

CONTAINER_NAME=$1
NEW_IMAGE=$2

# Check if container exists
if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container ${CONTAINER_NAME} does not exist"
    exit 1
fi

# Get current container info
echo "Getting current container configuration..."

# Extract relevant configuration with proper quoting and handling of empty values
NETWORK=$(docker inspect ${CONTAINER_NAME} --format '{{range $net, $v := .NetworkSettings.Networks}}{{$net}}{{end}}')
NETWORK_OPT=$([ ! -z "$NETWORK" ] && echo "--network $NETWORK")

VOLUMES=$(docker inspect ${CONTAINER_NAME} --format '{{range .Mounts}}--volume "{{.Source}}:{{.Destination}}{{if .Mode}}:{{.Mode}}{{end}}" {{end}}')

PORTS=$(docker inspect ${CONTAINER_NAME} --format '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}--publish "{{(index $conf 0).HostPort}}:{{$p}}" {{end}}{{end}}' | sed 's/\/tcp//')

ENV_VARS=$(docker inspect ${CONTAINER_NAME} --format '{{range .Config.Env}}--env "{{.}}" {{end}}')

RESTART_POLICY=$(docker inspect ${CONTAINER_NAME} --format '{{.HostConfig.RestartPolicy.Name}}')
RESTART_OPT=$([ ! -z "$RESTART_POLICY" ] && echo "--restart $RESTART_POLICY")

EXTRA_HOSTS=$(docker inspect ${CONTAINER_NAME} --format '{{range .HostConfig.ExtraHosts}}--add-host "{{.}}" {{end}}')

LABELS=$(docker inspect ${CONTAINER_NAME} --format '{{range $k, $v := .Config.Labels}}--label "{{$k}}={{$v}}" {{end}}')

# Stop and remove the old container
echo "Stopping container ${CONTAINER_NAME}..."
docker stop ${CONTAINER_NAME}
echo "Removing container ${CONTAINER_NAME}..."
docker rm ${CONTAINER_NAME}

# Create new container with the same configuration but new image
echo "Creating new container with image ${NEW_IMAGE}..."
DOCKER_CMD="docker run -d --name \"${CONTAINER_NAME}\" \
    ${NETWORK_OPT} \
    ${RESTART_OPT} \
    ${VOLUMES} \
    ${PORTS} \
    ${ENV_VARS} \
    ${EXTRA_HOSTS} \
    ${LABELS} \
    \"${NEW_IMAGE}\""

echo "Executing: ${DOCKER_CMD}"
eval ${DOCKER_CMD}

echo "Container ${CONTAINER_NAME} has been updated with image ${NEW_IMAGE}" 