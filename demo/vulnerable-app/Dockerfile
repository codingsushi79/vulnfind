FROM node:16
ARG NPM_TOKEN=npm_secretvalue123
ADD https://example.com/install.sh /tmp/install.sh
RUN curl -fsSL https://get.example.com/setup | bash
RUN chmod 777 /app
COPY . /app
EXPOSE 22 3000
CMD ["node", "web/server.js"]
