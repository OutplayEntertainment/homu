FROM python:3.4.3

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY . /usr/src/app
RUN pip install -e .

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

VOLUME ["/usr/src/app"]

EXPOSE 54856

CMD ["homu"]
