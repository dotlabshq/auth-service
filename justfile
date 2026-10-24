image := "ghcr.io/dotlabshq/auth-service"

build:
    pnpm update
    pnpm build

patch: build
    npm version patch --no-git-tag-version

# The image is built from the monorepo root with Dockerfile.workspace: this
# service depends on workspace packages (@baseworks/*) that a build from its
# own directory cannot see. The standalone Dockerfile that used to live here
# is gone for that reason.
build-docker tag="latest":
    docker build --platform linux/amd64 -f Dockerfile.workspace -t {{image}}:{{tag}} ../..

push-docker tag="latest":
    docker push {{image}}:{{tag}}

release-docker tag:
    just build-docker {{tag}}
    just push-docker {{tag}}

run tag="latest":
    docker run --rm -p 3000:3000 --env-file .env.local {{image}}:{{tag}}

dev:
    pnpm run dev
