APP = isuports

all: $(APP)

always:

### app

$(APP): webapp/go/*.go always
	cd webapp/go && go get && GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o ../../$(APP)

# deploy: $(APP) stop reset-logs scp scp-sql scp-env start
deploy: $(APP) stop reset-logs scp start

scp: $(APP)
	scp ./$(APP) isu01:/home/isucon/webapp/go/$(APP) & \
	scp ./$(APP) isu02:/home/isucon/webapp/go/$(APP) & \
	scp ./$(APP) isu03:/home/isucon/webapp/go/$(APP) & \
	wait

scp-sql:
	scp -r ./webapp/sql isu01:/home/isucon/webapp & \
	scp -r ./webapp/sql isu02:/home/isucon/webapp & \
	scp -r ./webapp/sql isu03:/home/isucon/webapp & \
	wait

scp-env:
	scp ./env.sh isu01:/home/isucon/env.sh & \
	scp ./env.sh isu02:/home/isucon/env.sh & \
	scp ./env.sh isu03:/home/isucon/env.sh & \
	wait

restart:
	ssh isu01 "sudo systemctl restart $(APP).go.service" & \
	ssh isu02 "sudo systemctl restart $(APP).go.service" & \
	ssh isu03 "sudo systemctl restart $(APP).go.service" & \
	wait

stop:
	ssh isu01 "sudo systemctl stop $(APP).go.service" & \
	ssh isu02 "sudo systemctl stop $(APP).go.service" & \
	ssh isu03 "sudo systemctl stop $(APP).go.service" & \
	wait

start:
	ssh isu01 "sudo systemctl start $(APP).go.service" & \
	ssh isu02 "sudo systemctl start $(APP).go.service" & \
	ssh isu03 "sudo systemctl start $(APP).go.service" & \
	wait

### nginx

deploy-nginx: scp-nginx reload-nginx

scp-nginx:
	ssh isu01 "sudo dd of=/etc/nginx/nginx.conf" < ./etc/nginx/nginx.conf
	ssh isu01 "sudo dd of=/etc/nginx/sites-available/$(APP).conf" < ./etc/nginx/sites-available/$(APP).conf
 
reload-nginx:
	ssh isu01 "sudo systemctl reload nginx.service"

reset-logs:
	ssh isu01 'sudo truncate -s 0 /var/log/nginx/access_log.ltsv'
	ssh isu01 'sudo truncate -s 0 /var/log/mysql/mysql-slow.log'

deploy-db: scp-db restart-db

scp-db:
	# ssh isu01 "sudo dd of=/etc/mysql/mysql.conf.d/mysqld.cnf" < ./etc/mysql/mysql.conf.d/mysqld.cnf
	# ssh isu02 "sudo dd of=/etc/mysql/mysql.conf.d/mysqld.cnf" < ./etc/mysql/mysql.conf.d/mysqld.cnf
	ssh isu03 "sudo dd of=/etc/mysql/mysql.conf.d/mysqld.cnf" < ./etc/mysql/mysql.conf.d/mysqld.cnf

restart-db:
	# ssh isu01 "sudo systemctl restart mysql.service" & \
	# ssh isu02 "sudo systemctl restart mysql.service"
	ssh isu03 "sudo systemctl restart mysql.service" & \
	wait

