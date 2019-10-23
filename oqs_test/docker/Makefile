IMAGENAME = ubuntu-oqssl
ALG=dilithium4
:
	@echo "Targets:"
	@echo "build{dev|run}: Create {development|execution only} Docker image"
	@echo "bash: Open root bash in Docker image"
	@echo "getopenssl: Retrieve openssl executable and config"
	@echo "push{dev|run}: Send {dev env | execution-only env} to Dockerhub"
	@echo "test: Test installation"
	@echo "clean: Clean folder"

builddev:
	docker build -t $(IMAGENAME) .

buildrun: 
	echo "If openssl folder is missing get it via make getopenssl"
	docker build -f Dockerfile-runonly -t $(IMAGENAME)-run .

pushrun:
	docker login && docker tag $(IMAGENAME)-run zrlmib/$(IMAGENAME)-run && docker push zrlmib/$(IMAGENAME)-run

smallspeed:
	docker run -t $(IMAGENAME)-run bash -c "oqs-speedtest dilithium4 kyber512"

pushdev:
	docker login && docker tag $(IMAGENAME) zrlmib/$(IMAGENAME)-dev && docker push zrlmib/$(IMAGENAME)-dev
	#docker build -t zrlmib/$(IMAGENAME) . && docker login && docker tag zrlmib/$(IMAGENAME) zrlmib/$(IMAGENAME) && docker push zrlmib/$(IMAGENAME)

bash:
	docker run -it $(IMAGENAME) bash

run:
	docker run -t $(IMAGENAME)

test:
	docker run -t $(IMAGENAME) oqs-speedtest dilithium4 kyber1024

ssltest: testprep
	docker network create --driver bridge ssltest-net
	docker run --name sslserver --network ssltest-net -h sslserver -v $(shell pwd)/tests:/root/tests -v $(shell pwd)/ssltest:/root/data -t $(IMAGENAME) /root/tests/ssltest.sh $(ALG) &
	sleep 5
	docker run --name sslclient --network ssltest-net -h sslclient -v $(shell pwd)/ssltest:/root/data -v $(shell pwd)/tests:/root/tests -t $(IMAGENAME) /root/tests/sslclient.sh $(ALG) 
	docker run --name sslspeedserver --network ssltest-net -h sslspeedserver -v $(shell pwd)/ssltest:/root/data -v $(shell pwd)/tests:/root/tests  -t $(IMAGENAME) /root/tests/ssltest.sh $(ALG) speed &
	sleep 5
	docker run --name sslspeedclient --network ssltest-net -h sslspeedclient -v $(shell pwd)/ssltest:/root/data -v $(shell pwd)/tests:/root/tests -t $(IMAGENAME) /root/tests/sslclient.sh $(ALG) newhope1024cca speed
	docker container rm sslspeedclient 
	docker run --name sslspeedclient --network ssltest-net -h sslspeedclient -v $(shell pwd)/ssltest:/root/data -v $(shell pwd)/tests:/root/tests -t $(IMAGENAME) /root/tests/sslclient.sh $(ALG) kyber512 speed

testprep:
	-docker stop sslserver 
	-docker stop sslclient 
	-docker container rm sslserver 
	-docker container rm sslclient 
	-docker stop sslspeedserver 
	-docker stop sslspeedclient 
	-docker container rm sslspeedserver 
	-docker container rm sslspeedclient 
	-docker network rm ssltest-net


getopenssl:
	rm -rf openssl
	mkdir -p openssl
	docker run -v $(shell pwd)/openssl:/root/oqssl -t $(IMAGENAME) bash -c "cp -R /usr/local/openssl/* /root/oqssl"

clean:
	rm -rf ../build ssl*.sh 
	sudo rm -rf openssl ssl data

clobber: clean
	-docker images -q | xargs docker rmi -f	
