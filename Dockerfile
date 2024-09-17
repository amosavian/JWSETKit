FROM swift:5.10

# Create app directory
RUN mkdir -p /usr/src/app

# Change working dir to /usr/src/app
WORKDIR /usr/src/app

VOLUME /usr/src/app

COPY Sources ./Sources
COPY Tests ./Tests
COPY Package.swift ./

EXEC swift test
