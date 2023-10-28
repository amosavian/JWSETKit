test:
	swift test

linuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm -v .:/usr/src/app linuxtest
