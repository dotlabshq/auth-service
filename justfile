image := "ghcr.io/dotlabshq/auth-service"

build tag="latest":
    docker build --platform linux/amd64 -t {{image}}:{{tag}} .

push tag="latest":
    docker push {{image}}:{{tag}}

release tag:
    just build {{tag}}
    just push {{tag}}

run tag="latest":
    docker run --rm -p 3000:3000 --env-file .env.local {{image}}:{{tag}}

dev:
    pnpm run dev
