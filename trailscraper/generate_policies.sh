for x in  ~/.trailscraper/logs/AWSLogs/877023909339/CloudTrail/us-east-1/2019/*/*/*.json.gz;
do
    if [ ! -f $x.policy ]; then
	echo $x;
	zcat $x | trailscraper generate > $x.policy;
    else
	echo $x.policy exists
    fi
done
