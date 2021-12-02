# Official Dart image: https://hub.docker.com/_/dart
# Specify the Dart SDK base image version using dart:<version> (ex: dart:2.12)
FROM dart:stable AS dartbuild

# Resolve app dependencies.
WORKDIR /app
COPY pubspec.* ./
RUN dart pub get

# Copy app source code and AOT compile it.
COPY . .
# Ensure packages are still up-to-date if anything has changed
RUN dart pub get --offline
RUN dart compile exe bin/accom_validation_server.dart -o bin/server


FROM node:16 as nodebuild

# Resolve app dependencies.
WORKDIR /app
COPY package.* ./
RUN npm install

# Copy app source code and build it.
COPY . .
RUN npm run build


FROM ubuntu:focal as intermediate

RUN apt-get update
RUN apt-get install -yq git rsync

RUN git clone https://github.com/UbuntuAccomplishments/desktop-accomplishments.git
RUN git clone https://github.com/UbuntuAccomplishments/community-accomplishments.git

RUN cd desktop-accomplishments && ./install.sh /accomplishments
RUN cd community-accomplishments && ./install.sh /accomplishments


# Build minimal serving image from AOT-compiled `/server` and required system
# libraries and configuration files stored in `/runtime/` from the build stage.
FROM ubuntu:focal

RUN apt-get update \
    && apt-get -yq install \
        python3 \
        python3-launchpadlib \
        python3-requests \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists

COPY --from=dartbuild /app/bin/server /app/bin/
COPY --from=intermediate /accomplishments /accomplishments

# Include files in the /public directory to enable static asset handling
COPY --from=nodebuild /app/public/ /public

# Start server.
EXPOSE 8080
CMD ["/app/bin/server"]