
#docker run Postgres 15, trust auth (for local testing only)
docker run --rm -p 5432:5432   -e POSTGRES_USER=rustlite   -e POSTGRES_DB=rustlite_test   -e POSTGRES_HOST_AUTH_METHOD=trust  --name pg-test postgres:15
