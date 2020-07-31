build :
	docker build . -t trailscraper

test :
	#docker run -it trailscraper  generate ~/devops/pyinsights/codebuild_data.json
	cat ~/devops/pyinsights/codebuild_data.json | docker run  -i  trailscraper  generate 
