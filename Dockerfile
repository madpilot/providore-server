FROM node:14
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
RUN apt upgrade && apt install openssl -y
RUN npm install -g providore
RUN mkdir /config /devices /tls /ca
EXPOSE 3000
ENTRYPOINT ["/tini", "--"]
CMD ["providore", "-c", "/config/config.json"]