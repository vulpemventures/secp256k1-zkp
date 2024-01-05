FROM emscripten/emsdk:3.1.40

RUN apt-get update
RUN apt-get install dh-autoreconf -y

WORKDIR /build
