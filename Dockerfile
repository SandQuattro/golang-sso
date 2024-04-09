#
# First stage:
# Building a backend.
#

FROM golang:1.21-alpine AS backend

# Move to a working directory (/build).
WORKDIR /build

# Copy and download dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code to the container.
COPY . .

# Set necessary environment variables needed for the image and build the server.
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Run go build (with ldflags to reduce binary size).
RUN go build -ldflags="-s -w" -o -sso ./cmd/sso

# Create a group and user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

#
# Third stage:
# Creating and running a new scratch container with the backend binary.
#

FROM scratch

# Copy binary and config files from /build to the respective folders in the scratch container.
COPY --from=backend ["/build/-sso", "/"]
COPY --from=backend ["/build/conf", "/conf"]

# Copy the user and group information
COPY --from=backend ["/etc/passwd", "/etc/passwd"]
COPY --from=backend ["/etc/group", "/etc/group"]

# Use the created user
USER appuser

# Command to run when starting the container.
ENTRYPOINT ["/-sso"]