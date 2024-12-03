# Dockerfile

# use the official Bun image
# see all versions at https://hub.docker.com/r/oven/bun/tags
FROM oven/bun:1 as base
WORKDIR /usr/src/app

# install dependencies into temp folder
# this will cache them and speed up future builds
FROM base AS install
RUN mkdir -p /temp/dev
COPY package.json bun.lockb /temp/dev/
RUN cd /temp/dev && bun install --frozen-lockfile

# copy node_modules and source code
FROM base AS release
COPY --from=install /temp/dev/node_modules node_modules
COPY . .

# run the app
RUN chown -R bun:bun .
USER bun
ENV NODE_ENV=production
EXPOSE 4000
ENTRYPOINT [ "bun", "index.js" ]
