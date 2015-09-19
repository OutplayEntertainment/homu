FROM python:3.4.3

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY . /usr/src/app
RUN pip install -e .

COPY docker-entrypoint.sh /
COPY cfg.env.toml ./cfg.env.toml
ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 32323

VOLUME ["/usr/src/app"]

CMD ["homu", "-c", "./cfg.env.toml"]
