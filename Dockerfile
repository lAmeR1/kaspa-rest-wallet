FROM node:21-slim

ENV NODE_ENV=production

WORKDIR /app

COPY ["package.json", "./"]

RUN npm update
RUN npm install --production

COPY . .
EXPOSE 3000

CMD [ "node", "main.js" ]
