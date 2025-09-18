1. Build the Docker Image

From the root folder of the project (where the Dockerfile is located), run:

    docker build -t sibpre-app .

This command builds the Docker image and tags it as `sibpre-app`.

-------------------------------------------------

2. Run the Container for Testing

To start a container from the image and test it, run:

    docker run --rm -it sibpre-app

- `--rm` ensures the container is removed after it stops.
- `-it` runs the container in interactive mode with a terminal.

You should now be inside the container and able to test the application.