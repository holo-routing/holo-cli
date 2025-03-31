# Docker

# Build

To build the Docker image, navigate to the parent directory and run the following command:
```
docker build -t holo-cli -f docker/Dockerfile .
```

By default, the build will use the `release` profile. If you want to build with a different profile, you can specify it using the `--build-arg` flag:
```
docker build --build-arg BUILD_PROFILE=dev -t holo-cli -f docker/Dockerfile .
```

Available build profiles:
- `release` (default): Optimized for production.
- `dev`: For development with debugging info.
- `small`: For smaller binaries.

# Running

To run the container, use the following command, adjusting the holod address as needed:
```
docker run -it holo-cli -a http://172.20.20.2:50051
```
