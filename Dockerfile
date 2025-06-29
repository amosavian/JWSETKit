FROM swift:6.1

# Add nonroot user
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot \
&& mkdir -p /home/nonroot \
&& chown -R nonroot:nonroot /home/nonroot \
&& mkdir -p /home/nonroot/src/app \
&& chown -R nonroot:nonroot /home/nonroot/src/app
USER nonroot

# Change working dir to /usr/src/app
WORKDIR /home/nonroot/src/app
VOLUME /home/nonroot/src/app

COPY Sources ./Sources
COPY Tests ./Tests
COPY Package.swift ./
ENTRYPOINT ["swift", "test"]
