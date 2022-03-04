# build stage
# build stage is used to optimize Docker image size
FROM node:lts-alpine as build-stage
WORKDIR /app

# copy npm relevant files
COPY package*.json ./
# install node_modules -> dependencies
RUN npm install
# copy application files
COPY ./ .
# build application -> compiling
RUN npm run build

# production stage
FROM nginx as production-stage
RUN mkdir /app
# copy compiled JavaScript files to folder that is used by nginx for delivery
COPY --from=build-stage /app/dist /app
# set up nginx.conf file
COPY nginx.conf /etc/nginx/nginx.conf