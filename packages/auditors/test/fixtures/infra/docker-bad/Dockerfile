# syntax=docker/dockerfile:1
FROM node
ARG NPM_TOKEN
ENV DB_PASSWORD=hunter2hunter2 \
    NODE_ENV=production
RUN apt-get update && \
    # install deps
    apt-get install -y gcc make curl
RUN curl -fsSL https://example.com/install.sh | sudo bash
RUN apk add git
ADD https://example.com/tool.tar.gz /opt/
ADD config.json /app/config.json
COPY . .
EXPOSE 22 3000
CMD ["node", "server.js"]
