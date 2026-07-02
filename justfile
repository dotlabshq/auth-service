image := "ghcr.io/dotlabshq/auth-service"

build:
    pnpm update
    pnpm build

patch: build
    npm version patch --no-git-tag-version

build-docker tag="latest":
    docker build --platform linux/amd64 -t {{image}}:{{tag}} .

push-docker tag="latest":
    docker push {{image}}:{{tag}}

release-docker tag:
    just build-docker {{tag}}
    just push-docker {{tag}}

run tag="latest":
    docker run --rm -p 3000:3000 --env-file .env.local {{image}}:{{tag}}

dev:
    pnpm run dev
