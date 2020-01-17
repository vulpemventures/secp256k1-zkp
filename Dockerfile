FROM apiaryio/emcc:latest

RUN apt-get update
RUN apt-get install dh-autoreconf -y
