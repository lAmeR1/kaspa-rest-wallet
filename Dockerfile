FROM node:16

ENV NODE_ENV=production

WORKDIR /app

COPY ["package.json", "./"]

RUN npm install --production

COPY . .
EXPOSE 3000

CMD [ "node", "main.js" ]
