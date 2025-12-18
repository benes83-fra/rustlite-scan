
docker run -d --name mysql_test -e MYSQL_ROOT_PASSWORD=rootpw -p 3306:3306 mysql:8.0
docker run -d --name mariadb_test -e MARIADB_ROOT_PASSWORD=rootpw -p 3307:3306 mariadb:10.11
