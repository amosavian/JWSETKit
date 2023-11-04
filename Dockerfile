FROM swift:latest

# Create app directory
RUN mkdir -p /usr/src/app

# Change working dir to /usr/src/app
WORKDIR /usr/src/app

VOLUME /usr/src/app

ADD Sources ./Sources
ADD Tests ./Tests
ADD Package.swift ./

CMD swift test
