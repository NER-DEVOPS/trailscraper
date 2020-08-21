FROM python:3.8-alpine as base
#FROM base as builder
#
FROM base
RUN apk add build-base

ADD requirements.txt /opt/trailscraper/requirements.txt
WORKDIR /opt/trailscraper/

RUN python3.8 -m pip install -r requirements.txt --upgrade
#RUN python3.8 -m pip install python.dateutil

ADD . /opt/trailscraper/
RUN python3.8 setup.py install

#COPY --from=builder /install /usr/local

ENTRYPOINT ["/usr/local/bin/trailscraper"]
