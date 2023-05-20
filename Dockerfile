FROM emscripten/emsdk:latest

RUN apt-get update
RUN apt-get install dh-autoreconf -y

WORKDIR /build
