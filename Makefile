build :
	docker build . -t trailscraper

test :
	 cat jdupont.json | DOCKER_HOST=tcp://localhost:2375 docker run  -i  106715121600.dkr.ecr.us-east-1.amazonaws.com/nrg-public:trailscraper  generate 
