#!/bin/sh

# dump initial data into mysql format

set -ex
datadir=initial_data
for sql in $(ls $datadir | grep '.db'); do
  ./webapp/sql/sqlite3-to-sql $datadir/$sql > $datadir/initial_data_mysql/$sql.sql
done
